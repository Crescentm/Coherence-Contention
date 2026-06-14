#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

void *hr_mode_contention_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 50000;
  int cpu = -1;
  uint64_t page_gpa = 0, other_gpa = 0, shared_gpa = 0;
  uint64_t log_off = 0;
  uint64_t last_cfg_seq = 0;
  int vm_fd = -1;
  int shared_fd = -1;
  uint64_t page_hpa = 0, other_hpa = 0, shared_hpa = 0;
  struct hr_reader_ctx page_reader = {.fd = -1};
  struct hr_reader_ctx other_reader = {.fd = -1};
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  uint64_t last_guest_seq = 0;
  FILE *fh1 = NULL, *fh0 = NULL, *meta = NULL;
  uint64_t first_seq = 0, last_seq = 0;
  int collected = 0;

  (void)arg;
  if (!outdir || !sync_log) {
    fprintf(stderr,
            "[HR/contention] missing env: HR_OUTDIR=%p HR_SYNC_LOG=%p\n",
            (void *)outdir, (void *)sync_log);
    return NULL;
  }
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);

  wait_file_exists(sync_log);
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
    fprintf(stderr,
            "[HR/contention] wait_probe_shared_gpa failed: sync_log=%s\n",
            sync_log);
    return NULL;
  }

  maybe_pin_cpu(cpu);
  for (int i = 0; i < 100; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR/contention] find_self_kvm_vm_fd failed\n");
    return NULL;
  }

  shared_ptr =
      map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, &shared_hpa);
  if (!shared_ptr) {
    fprintf(stderr,
            "[HR/contention] map_shared_counter_page failed: vm_fd=%d "
            "shared_gpa=0x%llx errno=%d (%s)\n",
            vm_fd, (unsigned long long)shared_gpa, errno, strerror(errno));
    return NULL;
  }
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr, "[HR/contention] mailbox magic timeout\n");
    goto done;
  }
  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR/contention] wait_guest_cfg timeout\n");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_CONTENTION) {
    fprintf(stderr, "[HR/contention] unexpected cfg_mode=%llu\n",
            (unsigned long long)cfg.mode);
    goto done;
  }
  page_gpa = cfg.target_gpa;
  other_gpa = cfg.other_gpa;
  if (hr_reader_open(&page_reader) != 0 ||
      hr_reader_open(&other_reader) != 0) {
    fprintf(stderr, "[HR/contention] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    goto done;
  }
  if (hr_reader_bind(&page_reader, vm_fd, page_gpa, HPA_READER_MODE_CIPHERTEXT) != 0 ||
      hr_reader_bind(&other_reader, vm_fd, other_gpa, HPA_READER_MODE_CIPHERTEXT) != 0) {
    fprintf(stderr,
            "[HR/contention] hr_reader_bind failed: page_gpa=0x%llx other_gpa=0x%llx errno=%d (%s)\n",
            (unsigned long long)page_gpa, (unsigned long long)other_gpa,
            errno, strerror(errno));
    goto done;
  }
  page_hpa = page_reader.page_hpa;
  other_hpa = other_reader.page_hpa;

  if (ensure_dir_p(outdir) != 0)
    goto done;

  {
    char h1_path[512], h0_path[512];
    snprintf(h1_path, sizeof(h1_path), "%s/raw_h1_cycles.csv", outdir);
    snprintf(h0_path, sizeof(h0_path), "%s/raw_h0_cycles.csv", outdir);
    fh1 = fopen(h1_path, "w");
    fh0 = fopen(h0_path, "w");
    if (!fh1 || !fh0)
      goto done;
    fprintf(fh1, "cycles\n");
    fprintf(fh0, "cycles\n");
  }

  {
    const int N_DRAIN = 200;
    for (int i = 0; i < N_DRAIN; i++) {
      uint64_t seq = 0;
      uint64_t warm = 0;
      if (hr_reader_measure_line(&other_reader, 0, &warm) != 0) {
        fprintf(stderr,
                "[HR/contention] warmup H0 measure failed: errno=%d (%s)\n",
                errno, strerror(errno));
        goto done;
      }
      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
        break;
      if (hr_reader_measure_line(&page_reader, 0, &warm) != 0) {
        fprintf(stderr,
                "[HR/contention] warmup H1 measure failed: errno=%d (%s)\n",
                errno, strerror(errno));
        goto done;
      }
      signal_sync_host_ack(sync_mb, seq);
      last_guest_seq = seq;
    }
  }

  while (collected < reps) {
    uint64_t seq = 0;
    uint64_t c_h0 = 0;
    uint64_t c_h1;
    if (hr_reader_measure_line(&other_reader, 0, &c_h0) != 0) {
      fprintf(stderr,
              "[HR/contention] H0 measure failed: errno=%d (%s)\n",
              errno, strerror(errno));
      goto done;
    }

    if (c_h0 == 0 || c_h0 > 100000)
      c_h0 = 9999;
    if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
      break;
    if (hr_reader_measure_line(&page_reader, 0, &c_h1) != 0) {
      fprintf(stderr,
              "[HR/contention] H1 measure failed: errno=%d (%s)\n",
              errno, strerror(errno));
      goto done;
    }
    signal_sync_host_ack(sync_mb, seq);
    last_guest_seq = seq;
    if (c_h1 == 0 || c_h1 > 100000)
      c_h1 = 9999;

    if (collected == 0)
      first_seq = seq;
    last_seq = seq;

    fprintf(fh1, "%llu\n", (unsigned long long)c_h1);
    fprintf(fh0, "%llu\n", (unsigned long long)c_h0);
    collected++;
  }

  {
    char meta_path[512], done_path[512];
    FILE *df;
    snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
    meta = fopen(meta_path, "w");
    if (meta) {
      fprintf(meta,
              "mode=contention-nocache\n"
              "sync_mode=shared-mem-counter\n"
              "page_gpa=0x%llx\n"
              "page_hpa=0x%llx\n"
              "other_page_gpa=0x%llx\n"
              "other_page_hpa=0x%llx\n"
              "shared_gpa=0x%llx\n"
              "shared_hpa=0x%llx\n"
              "reps=%d\n"
              "collected=%d\n"
              "first_sync_seq=%llu\n"
              "last_sync_seq=%llu\n"
              "cpu=%d\n",
              (unsigned long long)page_gpa, (unsigned long long)page_hpa,
              (unsigned long long)other_gpa, (unsigned long long)other_hpa,
              (unsigned long long)shared_gpa, (unsigned long long)shared_hpa,
              reps, collected, (unsigned long long)first_seq,
              (unsigned long long)last_seq, cpu);
      fclose(meta);
      meta = NULL;
    }

    snprintf(done_path, sizeof(done_path), "%s/contention_done.txt", outdir);
    df = fopen(done_path, "w");
    if (df) {
      fprintf(df, "collected=%d\nsync_mode=shared-mem-counter\n", collected);
      fclose(df);
    }
  }

done:
  hr_reader_close(&page_reader);
  hr_reader_close(&other_reader);
  if (fh1)
    fclose(fh1);
  if (fh0)
    fclose(fh0);
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

void *hr_main_thread_contention(void *arg) {
  return hr_mode_contention_impl(arg);
}
