#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

void *hr_mode_single_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 32;
  int cpu = -1;
  int victim_line = 0;
  int page_kind = 0;
  uint64_t threshold = 400;
  uint32_t probe_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE;
  uint32_t reader_mode = HPA_READER_MODE_CIPHERTEXT_CACHEABLE;
  uint64_t target_gpa = 0, other_gpa = 0, shared_gpa = 0;
  uint64_t log_off = 0;
  uint64_t last_cfg_seq = 0;
  int vm_fd = -1;
  int shared_fd = -1;
  uint64_t shared_hpa = 0, target_hpa = 0;
  struct hr_reader_ctx reader = {.fd = -1};
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  uint64_t last_guest_seq = 0;
  FILE *csv = NULL, *meta = NULL, *rf = NULL;
  char csv_path[512], meta_path[512];
  const char *raw_file;
  unsigned raw_pending = 0;

  (void)arg;
  if (!outdir || !sync_log) {
    fprintf(stderr, "[HR/single] missing env: HR_OUTDIR=%p HR_SYNC_LOG=%p\n",
            (void *)outdir, (void *)sync_log);
    return NULL;
  }
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);
  if ((env = getenv("HR_VICTIM_LINE")))
    victim_line = atoi(env);
  if ((env = getenv("HR_PAGE_KIND")) && strcmp(env, "other") == 0)
    page_kind = 1;
  if ((env = getenv("HR_THRESHOLD")))
    threshold = strtoull(env, NULL, 0);
  if ((env = getenv("HR_NOCACHE")) && atoi(env) == 1)
    probe_mode = KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE;
  reader_mode = hr_probe_mode_to_reader_mode(probe_mode);
  if (reader_mode == UINT32_MAX) {
    fprintf(stderr, "[HR/single] unsupported probe_mode=%u\n", probe_mode);
    return NULL;
  }

  wait_file_exists(sync_log);
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
    fprintf(stderr, "[HR/single] wait_probe_shared_gpa failed: sync_log=%s\n",
            sync_log);
    return NULL;
  }

  maybe_pin_cpu(cpu);
  for (int i = 0; i < 50; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }

  if (vm_fd < 0) {
    fprintf(stderr, "[HR/single] find_self_kvm_vm_fd failed\n");
    return NULL;
  }

  shared_ptr =
      map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, &shared_hpa);
  if (!shared_ptr) {
    fprintf(stderr,
            "[HR/single] map_shared_counter_page failed: vm_fd=%d "
            "shared_gpa=0x%llx errno=%d (%s)\n",
            vm_fd, (unsigned long long)shared_gpa, errno, strerror(errno));
    return NULL;
  }
  fprintf(stderr, "[HR/single] shared mapped: shared_hpa=0x%llx via=%s\n",
          (unsigned long long)shared_hpa,
          shared_fd >= 0 ? "hpa_reader_mmap" : "kvm_gpa_hva");
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr,
            "[HR/single] mailbox magic timeout: shared_gpa=0x%llx "
            "shared_hpa=0x%llx magic=0x%llx\n",
            (unsigned long long)shared_gpa, (unsigned long long)shared_hpa,
            (unsigned long long)__atomic_load_n(
                (const uint64_t *)&sync_mb->phase_magic, __ATOMIC_ACQUIRE));
    goto done;
  }
  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR/single] wait_guest_cfg timeout\n");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_SYNC) {
    fprintf(stderr, "[HR/single] unexpected cfg_mode=%llu\n",
            (unsigned long long)cfg.mode);
    goto done;
  }
  target_gpa = cfg.target_gpa;
  other_gpa = cfg.other_gpa;

  if (page_kind == 1)
    target_gpa = other_gpa;
  if (hr_reader_open(&reader) != 0) {
    fprintf(stderr, "[HR/single] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    goto done;
  }
  if (hr_reader_bind(&reader, vm_fd, target_gpa, reader_mode) != 0) {
    fprintf(stderr,
            "[HR/single] hr_reader_bind failed: target_gpa=0x%llx mode=%u errno=%d (%s)\n",
            (unsigned long long)target_gpa, reader_mode, errno, strerror(errno));
    goto done;
  }
  target_hpa = reader.page_hpa;
  if (target_hpa == 0)
    target_hpa = 0;

  if (ensure_dir_p(outdir) != 0) {
    fprintf(stderr,
            "[HR/single] ensure_dir_p failed: outdir=%s errno=%d (%s)\n",
            outdir, errno, strerror(errno));
    goto done;
  }

  snprintf(csv_path, sizeof(csv_path), "%s/line_matrix_row.csv", outdir);
  snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
  csv = fopen(csv_path, "w");
  meta = fopen(meta_path, "w");
  if (!csv || !meta) {
    fprintf(stderr,
            "[HR/single] fopen output failed: csv=%s meta=%s errno=%d (%s)\n",
            csv_path, meta_path, errno, strerror(errno));
    goto done;
  }

  fprintf(csv, "host_line,mean_cycles,min_cycles,max_cycles,p_gt_t,reps\n");

  raw_file = getenv("HR_RAW_FILE");
  if (raw_file) {
    rf = fopen(raw_file, "w");
    if (rf)
      fprintf(rf, "cycles\n");
  }

  for (int line = 0; line < (int)LINES; line++) {
    uint64_t sum = 0, min_ = ~0ULL, max_ = 0, over = 0;
    int samples = 0;
    for (int rep = 0; rep < reps; rep++) {
      uint64_t seq = 0;
      uint64_t cycles;
      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
        break;
      if (hr_reader_measure_line(&reader, line, &cycles) != 0) {
        fprintf(stderr,
                "[HR/single] hr_reader_measure_line failed: line=%d errno=%d (%s)\n",
                line, errno, strerror(errno));
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
      if (rf && line == victim_line) {
        fprintf(rf, "%llu\n", (unsigned long long)cycles);
        if (++raw_pending >= 256) {
          fflush(rf);
          raw_pending = 0;
        }
      }
    }
    if (samples == 0)
      break;
    fprintf(csv, "%d,%.6f,%llu,%llu,%.9f,%u\n", line, (double)sum / samples,
            (unsigned long long)min_, (unsigned long long)max_,
            (double)over / samples, samples);
    fflush(csv);
  }

  fprintf(meta,
          "target_gpa=0x%llx\n"
          "target_hpa=0x%llx\n"
          "shared_gpa=0x%llx\n"
          "shared_hpa=0x%llx\n"
          "victim_line=%d\n"
          "page_kind=%s\n"
          "mode=%s\n"
          "reps=%d\n",
          (unsigned long long)target_gpa, (unsigned long long)target_hpa,
          (unsigned long long)shared_gpa, (unsigned long long)shared_hpa,
          victim_line, page_kind ? "other" : "same",
          probe_mode == KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE
              ? "ciphertext-nocache"
              : "ciphertext-cacheable",
          reps);

done:
  hr_reader_close(&reader);
  if (rf && raw_pending > 0)
    fflush(rf);
  if (rf)
    fclose(rf);
  if (csv)
    fclose(csv);
  if (meta)
    fclose(meta);
  if (shared_ptr && shared_fd >= 0)
    munmap((void *)shared_ptr, PAGE_SZ);
  if (shared_fd >= 0)
    close(shared_fd);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_single(void *arg) { return hr_mode_single_impl(arg); }
