#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

void *hr_mode_all_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 32;
  int cpu = -1;
  int raw_focus_vline = 0;
  int host_lines_per_victim = (int)LINES;
  int start_line = 0;
  uint64_t threshold = 400;
  uint32_t probe_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE;
  uint32_t reader_mode = HPA_READER_MODE_CIPHERTEXT_CACHEABLE;
  uint64_t page_gpa = 0, other_gpa = 0, shared_gpa = 0;
  uint64_t log_off = 0;
  uint64_t last_cfg_seq = 0;
  int vm_fd = -1;
  int shared_fd = -1;
  uint64_t shared_hpa = 0;
  struct hr_reader_ctx reader = {.fd = -1};
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  uint64_t last_guest_seq = 0;
  uint64_t last_phase_seq = 0;
  FILE *raw_h1_fp = NULL, *raw_h0_fp = NULL;
  int all_done = 0;

  (void)arg;
  if (!outdir || !sync_log) {
    fprintf(stderr, "[HR] missing env: HR_OUTDIR=%p HR_SYNC_LOG=%p\n",
            (void *)outdir, (void *)sync_log);
    return NULL;
  }
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);
  if ((env = getenv("HR_THRESHOLD")))
    threshold = strtoull(env, NULL, 0);
  if ((env = getenv("HR_RAW_FOCUS_VLINE")))
    raw_focus_vline = atoi(env);
  if ((env = getenv("HR_HOST_LINES_PER_VICTIM")))
    host_lines_per_victim = atoi(env);
  if ((env = getenv("HR_NOCACHE")) && atoi(env) == 1)
    probe_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE;
  reader_mode = hr_probe_mode_to_reader_mode(probe_mode);
  if (reader_mode == UINT32_MAX) {
    fprintf(stderr, "[HR] unsupported probe_mode=%u\n", probe_mode);
    return NULL;
  }

  if (host_lines_per_victim <= 0 || host_lines_per_victim > (int)LINES)
    host_lines_per_victim = (int)LINES;
  if (host_lines_per_victim < (int)LINES)
    start_line = raw_focus_vline;
  if (start_line < 0)
    start_line = 0;
  if (start_line >= (int)LINES)
    start_line = (int)LINES - 1;
  if (start_line + host_lines_per_victim > (int)LINES)
    host_lines_per_victim = (int)LINES - start_line;

  maybe_pin_cpu(cpu);
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0)
    return NULL;

  for (int i = 0; i < 100; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR] find_self_kvm_vm_fd failed\n");
    return NULL;
  }
  if (hr_reader_open(&reader) != 0) {
    fprintf(stderr, "[HR] open %s failed: errno=%d (%s)\n", HPA_READER_DEV,
            errno, strerror(errno));
    close(vm_fd);
    return NULL;
  }

  fprintf(stderr, "[HR] vm_fd=%d, mapping shared_gpa=0x%llx\n", vm_fd,
          (unsigned long long)shared_gpa);
  shared_ptr =
      map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, &shared_hpa);
  if (!shared_ptr) {
    fprintf(stderr,
            "[HR] map_shared_counter_page failed: vm_fd=%d "
            "shared_gpa=0x%llx errno=%d (%s)\n",
            vm_fd, (unsigned long long)shared_gpa, errno, strerror(errno));
    return NULL;
  }
  fprintf(stderr, "[HR] shared mapped: shared_hpa=0x%llx via=%s\n",
          (unsigned long long)shared_hpa,
          shared_fd >= 0 ? "hpa_reader_mmap" : "kvm_gpa_hva");
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  if (wait_mailbox_magic(sync_mb, 30.0) != 0) {
    fprintf(stderr,
            "[HR] mailbox magic timeout: shared_gpa=0x%llx shared_hpa=0x%llx "
            "magic=0x%llx\n",
            (unsigned long long)shared_gpa, (unsigned long long)shared_hpa,
            (unsigned long long)__atomic_load_n(
                (const uint64_t *)&sync_mb->phase_magic, __ATOMIC_ACQUIRE));
    goto done;
  }

  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  {
    uint64_t phase_seq_now = __atomic_load_n(
        (const uint64_t *)&sync_mb->phase_seq, __ATOMIC_ACQUIRE);
    uint64_t phase_ack_now = __atomic_load_n(
        (const uint64_t *)&sync_mb->phase_ack, __ATOMIC_ACQUIRE);
    if (phase_ack_now > phase_seq_now)
      phase_ack_now = phase_seq_now;
    last_phase_seq = phase_ack_now;
    fprintf(stderr,
            "[HR] mailbox ready: guest_seq=%llu phase_seq=%llu phase_ack=%llu "
            "last_phase_seq=%llu\n",
            (unsigned long long)last_guest_seq,
            (unsigned long long)phase_seq_now, (unsigned long long)phase_ack_now,
            (unsigned long long)last_phase_seq);
  }

  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR] wait_guest_cfg timeout in all mode\n");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_SYNC_ALL) {
    fprintf(stderr, "[HR] unexpected cfg_mode=%llu in all mode\n",
            (unsigned long long)cfg.mode);
    goto done;
  }
  page_gpa = cfg.page_gpa;
  other_gpa = cfg.other_gpa;
  (void)page_gpa;
  (void)other_gpa;
  if (cfg.host_lines > 0 && cfg.host_lines <= LINES)
    host_lines_per_victim = (int)cfg.host_lines;
  if (cfg.reps > 0)
    reps = (int)cfg.reps;

  if (host_lines_per_victim <= 0 || host_lines_per_victim > (int)LINES)
    host_lines_per_victim = (int)LINES;
  if (host_lines_per_victim < (int)LINES)
    start_line = raw_focus_vline;
  if (start_line < 0)
    start_line = 0;
  if (start_line >= (int)LINES)
    start_line = (int)LINES - 1;
  if (start_line + host_lines_per_victim > (int)LINES)
    host_lines_per_victim = (int)LINES - start_line;

  if (ensure_dir_p(outdir) != 0) {
    fprintf(stderr, "[HR] ensure_dir_p FAILED for outdir=%s errno=%d (%s)\n",
            outdir, errno, strerror(errno));
    goto done;
  }

  {
    char p1[512], p0[512];
    snprintf(p1, sizeof(p1), "%s/raw_h1_cycles.csv", outdir);
    snprintf(p0, sizeof(p0), "%s/raw_h0_cycles.csv", outdir);
    raw_h1_fp = fopen(p1, "w");
    raw_h0_fp = fopen(p0, "w");
    if (raw_h1_fp)
      fprintf(raw_h1_fp, "cycles\n");
    if (raw_h0_fp)
      fprintf(raw_h0_fp, "cycles\n");
  }

  while (!all_done) {
    uint64_t phase_seq = 0;
    uint64_t phase_kind = 0;
    uint64_t victim_line = 0;
    uint64_t target_gpa = 0, target_hpa = 0;
    char dpath[512], csv_path[1024], meta_path[1024];
    FILE *csv = NULL, *meta = NULL;
    int rows_completed = 0;

    if (wait_phase_guest_seq(sync_mb, last_phase_seq, 60.0, &phase_seq) != 0)
      break;
    phase_kind = __atomic_load_n((const uint64_t *)&sync_mb->phase_kind,
                                 __ATOMIC_ACQUIRE);
    victim_line = __atomic_load_n((const uint64_t *)&sync_mb->phase_vline,
                                  __ATOMIC_ACQUIRE);
    target_gpa = __atomic_load_n((const uint64_t *)&sync_mb->phase_target_gpa,
                                 __ATOMIC_ACQUIRE);

    if (phase_kind != SYNC_PHASE_DONE &&
        (phase_kind > 1 || victim_line >= LINES ||
         (target_gpa & (PAGE_SZ - 1ULL)) != 0))
      break;

    signal_phase_host_ack(sync_mb, phase_seq);
    last_phase_seq = phase_seq;

    if (phase_kind == SYNC_PHASE_DONE) {
      all_done = 1;
      break;
    }

    snprintf(dpath, sizeof(dpath), "%s/victim_line_%02llu/%s_page", outdir,
             (unsigned long long)victim_line,
             phase_kind == 0 ? "same" : "other");
    if (ensure_dir_p(dpath) != 0)
      continue;

    snprintf(csv_path, sizeof(csv_path), "%s/line_matrix_row.csv", dpath);
    snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", dpath);
    csv = fopen(csv_path, "w");
    meta = fopen(meta_path, "w");
    if (!csv || !meta) {
      if (csv)
        fclose(csv);
      if (meta)
        fclose(meta);
      continue;
    }

    fprintf(csv, "host_line,mean_cycles,min_cycles,max_cycles,p_gt_t,reps\n");
    if (hr_reader_bind(&reader, vm_fd, target_gpa, reader_mode) != 0) {
      fprintf(stderr,
              "[HR] hr_reader_bind failed: target_gpa=0x%llx mode=%u errno=%d (%s)\n",
              (unsigned long long)target_gpa, reader_mode, errno,
              strerror(errno));
      fclose(csv);
      fclose(meta);
      csv = NULL;
      meta = NULL;
      goto done;
    }
    target_hpa = reader.page_hpa;

    for (int line = start_line; line < start_line + host_lines_per_victim;
         line++) {
      uint64_t sum = 0, min_ = ~0ULL, max_ = 0, over = 0;
      int samples = 0;
      for (int rep = 0; rep < reps; rep++) {
        uint64_t seq = 0;
        uint64_t cycles;
        if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
          break;
        if (hr_reader_measure_line(&reader, line, &cycles) != 0) {
          fprintf(stderr,
                  "[HR] hr_reader_measure_line failed: target_gpa=0x%llx line=%d errno=%d (%s)\n",
                  (unsigned long long)target_gpa, line, errno, strerror(errno));
          fclose(csv);
          fclose(meta);
          csv = NULL;
          meta = NULL;
          goto done;
        }
        if (cycles == 0)
          cycles = 9999;
        signal_sync_host_ack(sync_mb, seq);
        last_guest_seq = seq;
        sum += cycles;
        if (cycles < min_)
          min_ = cycles;
        if (cycles > max_)
          max_ = cycles;
        if (cycles > threshold)
          over++;
        samples++;
        if (line == raw_focus_vline &&
            victim_line == (uint64_t)raw_focus_vline) {
          if (phase_kind == 0 && raw_h1_fp)
            fprintf(raw_h1_fp, "%llu\n", (unsigned long long)cycles);
          if (phase_kind == 1 && raw_h0_fp)
            fprintf(raw_h0_fp, "%llu\n", (unsigned long long)cycles);
        }
      }
      if (samples == 0)
        break;
      fprintf(csv, "%d,%.6f,%llu,%llu,%.9f,%u\n", line, (double)sum / samples,
              (unsigned long long)min_, (unsigned long long)max_,
              (double)over / samples, samples);
      fflush(csv);
      rows_completed++;
    }

    fprintf(meta,
            "target_gpa=0x%llx\n"
            "target_hpa=0x%llx\n"
            "shared_gpa=0x%llx\n"
            "shared_hpa=0x%llx\n"
            "victim_line=%llu\n"
            "page_kind=%s\n"
            "rows_completed=%d\n"
            "reps=%d\n",
            (unsigned long long)target_gpa, (unsigned long long)target_hpa,
            (unsigned long long)shared_gpa, (unsigned long long)shared_hpa,
            (unsigned long long)victim_line, phase_kind == 0 ? "same" : "other",
            rows_completed, reps);
    fclose(csv);
    fclose(meta);
  }

  {
    char done_path[512];
    FILE *df;
    snprintf(done_path, sizeof(done_path), "%s/all_done.txt", outdir);
    df = fopen(done_path, "w");
    if (df) {
      fprintf(df, "DONE\n");
      fclose(df);
    }
  }

done:
  hr_reader_close(&reader);
  if (raw_h1_fp)
    fclose(raw_h1_fp);
  if (raw_h0_fp)
    fclose(raw_h0_fp);
  if (shared_ptr && shared_fd >= 0)
    munmap((void *)shared_ptr, PAGE_SZ);
  if (shared_fd >= 0)
    close(shared_fd);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_all(void *arg) { return hr_mode_all_impl(arg); }
