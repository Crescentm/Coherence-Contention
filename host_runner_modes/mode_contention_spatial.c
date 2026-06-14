#define _GNU_SOURCE

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

static void write_heartbeat(const char *hb_path, const char *stage,
                            int probe_line, int h0_n, int h1_n,
                            uint64_t last_seq, const char *detail) {
  FILE *fp;
  if (!hb_path || !*hb_path)
    return;
  fp = fopen(hb_path, "w");
  if (!fp)
    return;
  fprintf(fp,
          "stage=%s\n"
          "probe_line=%d\n"
          "h0_n=%d\n"
          "h1_n=%d\n"
          "last_seq=%llu\n"
          "detail=%s\n",
          stage ? stage : "unknown",
          probe_line,
          h0_n,
          h1_n,
          (unsigned long long)last_seq,
          detail ? detail : "none");
  fclose(fp);
}

void *hr_mode_contention_spatial_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 3000;
  int cpu = -1;
  int vm_fd = -1;
  int shared_fd = -1;
  uint64_t shared_gpa = 0;
  uint64_t log_off = 0;
  uint64_t last_cfg_seq = 0;
  uint64_t page_gpa = 0;
  uint64_t target_gpa = 0;
  uint64_t shared_hpa = 0;
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  uint64_t last_guest_seq = 0;
  struct hr_reader_ctx page_reader = {.fd = -1};
  FILE *csv = NULL;
  FILE *raw = NULL;
  FILE *meta = NULL;
  FILE *done = NULL;
  char csv_path[512], raw_path[512], meta_path[512], done_path[512], hb_path[512];
  const char *error_reason = "none";
  int probe_line_cur = -1;

  (void)arg;
  if (!outdir || !sync_log)
    return NULL;
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);

  snprintf(hb_path, sizeof(hb_path), "%s/contention_spatial_heartbeat.txt",
           outdir ? outdir : ".");
  write_heartbeat(hb_path, "init", probe_line_cur, 0, 0, 0, "thread_started");

  fprintf(stderr, "[HR/cont_spatial] waiting sync_log=%s\n", sync_log);
  wait_file_exists(sync_log);
  write_heartbeat(hb_path, "wait_probe_shared_gpa", probe_line_cur, 0, 0, 0,
                  "waiting_sync_log_probe_line");
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
    fprintf(stderr, "[HR/cont_spatial] wait_probe_shared_gpa failed\n");
    error_reason = "wait_probe_shared_gpa_failed";
    return NULL;
  }
  fprintf(stderr, "[HR/cont_spatial] shared_gpa=0x%llx\n",
          (unsigned long long)shared_gpa);

  maybe_pin_cpu(cpu);
  write_heartbeat(hb_path, "find_vm_fd", probe_line_cur, 0, 0, 0,
                  "search_kvm_vm_fd");
  for (int i = 0; i < 100; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR/cont_spatial] find_self_kvm_vm_fd failed\n");
    error_reason = "find_self_kvm_vm_fd_failed";
    return NULL;
  }
  fprintf(stderr, "[HR/cont_spatial] vm_fd=%d\n", vm_fd);

  write_heartbeat(hb_path, "map_shared_counter", probe_line_cur, 0, 0, 0,
                  "map_shared_counter_page");
  shared_ptr = map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, &shared_hpa);
  if (!shared_ptr) {
    fprintf(stderr, "[HR/cont_spatial] map_shared_counter_page failed\n");
    error_reason = "map_shared_counter_page_failed";
    return NULL;
  }
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  write_heartbeat(hb_path, "wait_mailbox_magic", probe_line_cur, 0, 0, 0,
                  "waiting_mailbox_magic");
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr, "[HR/cont_spatial] mailbox magic timeout\n");
    error_reason = "mailbox_magic_timeout";
    goto done;
  }
  fprintf(stderr, "[HR/cont_spatial] mailbox magic ok\n");
  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  write_heartbeat(hb_path, "wait_guest_cfg", probe_line_cur, 0, 0, last_guest_seq,
                  "waiting_cfg_ready");
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR/cont_spatial] wait_guest_cfg timeout\n");
    error_reason = "wait_guest_cfg_timeout";
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_CONTENTION_SPATIAL) {
    fprintf(stderr, "[HR/cont_spatial] unexpected cfg_mode=%llu\n",
            (unsigned long long)cfg.mode);
    error_reason = "unexpected_cfg_mode";
    goto done;
  }
  fprintf(stderr,
          "[HR/cont_spatial] cfg ok: target_gpa=0x%llx page_gpa=0x%llx victim_line=%llu reps=%d\n",
          (unsigned long long)cfg.target_gpa,
          (unsigned long long)cfg.page_gpa,
          (unsigned long long)cfg.dec_line,
          reps);
  target_gpa = cfg.target_gpa;
  page_gpa = cfg.page_gpa;

  if (hr_reader_open(&page_reader) != 0) {
    fprintf(stderr, "[HR/cont_spatial] open %s failed: %s\n",
            HPA_READER_DEV, strerror(errno));
    error_reason = "open_hpa_reader_failed";
    goto done;
  }
  if (hr_reader_bind(&page_reader, vm_fd, page_gpa, HPA_READER_MODE_CIPHERTEXT) != 0) {
    fprintf(stderr,
            "[HR/cont_spatial] hr_reader_bind failed: page_gpa=0x%llx errno=%d (%s)\n",
            (unsigned long long)page_gpa, errno, strerror(errno));
    error_reason = "hr_reader_bind_failed";
    goto done;
  }
  fprintf(stderr, "[HR/cont_spatial] reader bound: page_hpa=0x%llx\n",
          (unsigned long long)page_reader.page_hpa);

  if (ensure_dir_p(outdir) != 0)
    goto done;
  snprintf(csv_path, sizeof(csv_path), "%s/spatial_scan.csv", outdir);
  snprintf(raw_path, sizeof(raw_path), "%s/spatial_scan_raw.csv", outdir);
  snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
  snprintf(done_path, sizeof(done_path), "%s/contention_spatial_done.txt", outdir);
  csv = fopen(csv_path, "w");
  raw = fopen(raw_path, "w");
  meta = fopen(meta_path, "w");
  if (!csv || !raw || !meta)
    goto done;
  fprintf(csv, "probe_line,h0_mean,h1_mean,h0_std,h1_std,delta,h0_n,h1_n\n");
  fprintf(raw, "probe_line,phase,seq,cycles\n");

  for (int probe_line = 0; probe_line < (int)LINES; probe_line++) {
    int h0_n = 0, h1_n = 0;
    double h0_sum = 0.0, h1_sum = 0.0;
    double h0_sumsq = 0.0, h1_sumsq = 0.0;
    probe_line_cur = probe_line;
    fprintf(stderr, "[HR/cont_spatial] scan probe_line=%d start\n", probe_line);
    write_heartbeat(hb_path, "scan_line_start", probe_line_cur, h0_n, h1_n,
                    last_guest_seq, "collect_h0_h1");

    while (h0_n < reps || h1_n < reps) {
      uint64_t seq = 0;
      uint64_t c_h0 = 0;
      uint64_t c_h1 = 0;

      if (hr_reader_measure_line(&page_reader, probe_line, &c_h0) != 0) {
        fprintf(stderr,
                "[HR/cont_spatial] hr_reader_measure_line(H0) failed line=%d errno=%d (%s)\n",
                probe_line, errno, strerror(errno));
        error_reason = "hr_reader_measure_line_h0_failed";
        goto done;
      }
      if (c_h0 == 0 || c_h0 > 100000)
        c_h0 = 9999;
      h0_n++;
      h0_sum += (double)c_h0;
      h0_sumsq += (double)c_h0 * (double)c_h0;
      fprintf(raw, "%d,H0,%llu,%llu\n", probe_line,
              (unsigned long long)last_guest_seq, (unsigned long long)c_h0);

      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0) {
        fprintf(stderr, "[HR/cont_spatial] wait_sync_guest_seq timeout line=%d\n",
                probe_line);
        error_reason = "wait_sync_guest_seq_timeout";
        goto done;
      }
      if (hr_reader_measure_line(&page_reader, probe_line, &c_h1) != 0) {
        fprintf(stderr,
                "[HR/cont_spatial] hr_reader_measure_line(H1) failed line=%d errno=%d (%s)\n",
                probe_line, errno, strerror(errno));
        error_reason = "hr_reader_measure_line_h1_failed";
        goto done;
      }
      signal_sync_host_ack(sync_mb, seq);
      last_guest_seq = seq;
      if (c_h1 == 0 || c_h1 > 100000)
        c_h1 = 9999;
      h1_n++;
      h1_sum += (double)c_h1;
      h1_sumsq += (double)c_h1 * (double)c_h1;
      fprintf(raw, "%d,H1,%llu,%llu\n", probe_line,
              (unsigned long long)seq, (unsigned long long)c_h1);

      if (((h0_n + h1_n) & 0xFF) == 0)
        write_heartbeat(hb_path, "scan_line_progress", probe_line_cur, h0_n, h1_n,
                        last_guest_seq, "sample_checkpoint");

      if (h0_n >= reps && h1_n >= reps)
        break;
    }

    {
      double h0_mean = h0_sum / (double)h0_n;
      double h1_mean = h1_sum / (double)h1_n;
      double h0_var = (h0_sumsq / (double)h0_n) - h0_mean * h0_mean;
      double h1_var = (h1_sumsq / (double)h1_n) - h1_mean * h1_mean;
      double h0_std = h0_var > 0.0 ? sqrt(h0_var) : 0.0;
      double h1_std = h1_var > 0.0 ? sqrt(h1_var) : 0.0;
      fprintf(csv, "%d,%.6f,%.6f,%.6f,%.6f,%.6f,%d,%d\n",
              probe_line, h0_mean, h1_mean, h0_std, h1_std,
              h1_mean - h0_mean, h0_n, h1_n);
      fflush(csv);
      fprintf(stderr,
              "[HR/cont_spatial] scan probe_line=%d done h0_mean=%.1f h1_mean=%.1f delta=%.1f\n",
              probe_line, h0_mean, h1_mean, h1_mean - h0_mean);
    }
  }

  fprintf(meta,
          "mode=contention-spatial\n"
          "host_probe_mode=ciphertext-nocache\n"
          "host_probe_mapping=decrypted_nocache\n"
          "host_h0_definition=probe_other_page_same_offset_before_sync\n"
          "host_h1_definition=probe_target_page_same_offset_after_sync_before_ack\n"
          "guest_mode=contention_spatial\n"
          "guest_h1_sequence=clflush(target_line)_load(target_line)_signal_host_then_hammer_until_ack\n"
          "guest_h0_sequence=idle_then_signal_host\n"
          "page_gpa=0x%llx\n"
          "page_hpa=0x%llx\n"
          "target_gpa=0x%llx\n"
          "victim_line=%llu\n"
          "reps=%d\n"
          "cpu=%d\n"
          "raw_csv=%s\n",
          (unsigned long long)page_gpa,
          (unsigned long long)page_reader.page_hpa,
          (unsigned long long)target_gpa,
          (unsigned long long)cfg.dec_line,
          reps,
          cpu,
          raw_path);
  fflush(meta);

  done = fopen(done_path, "w");
  if (done) {
    fprintf(done, "status=ok\nreps=%d\nvictim_line=%llu\n", reps,
            (unsigned long long)cfg.dec_line);
    fflush(done);
  }

done:
  write_heartbeat(hb_path, "done", probe_line_cur, 0, 0, last_guest_seq,
                  error_reason);
  hr_reader_close(&page_reader);
  if (csv)
    fclose(csv);
  if (raw)
    fclose(raw);
  if (meta)
    fclose(meta);
  if (done)
    fclose(done);
  if (shared_ptr && shared_fd >= 0)
    munmap((void *)shared_ptr, PAGE_SZ);
  if (shared_fd >= 0)
    close(shared_fd);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_contention_spatial(void *arg) {
  return hr_mode_contention_spatial_impl(arg);
}
