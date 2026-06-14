#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

static void write_heartbeat(const char *hb_path, const char *stage,
                            int collected, uint64_t last_seq,
                            const char *detail) {
  FILE *fp;
  if (!hb_path || !*hb_path)
    return;
  fp = fopen(hb_path, "w");
  if (!fp)
    return;
  fprintf(fp,
          "stage=%s\n"
          "collected=%d\n"
          "last_seq=%llu\n"
          "detail=%s\n",
          stage ? stage : "unknown", collected,
          (unsigned long long)last_seq, detail ? detail : "none");
  fclose(fp);
}

/*
 * mode_contention_cacheable — 实验 4.2.3.2 / 4.2.4 H1_cont
 *
 * 与 mode_contention 的区别：
 *   - 使用 CIPHERTEXT_CACHEABLE（而非 NOCACHE）
 *   - 每次探测前通过 KVM_AMD_READ_GPA_BATCH(nr=1, F_CLFLUSH_EACH) 强制 clflush，
 *     排除一致性信号，只保留内存总线竞争信号
 *
 * 宿主机测量协议（与 mode_contention 相同）：
 *   H0: 在 guest sync 前测量 other_gpa（guest 不访问该行）
 *   H1: 在 guest sync 后测量 page_gpa（guest 刚完成 CLFLUSH+load）
 *
 * 需要 guest 以 probe_mode=contention 运行。
 */

/* 持久映射路径：先 CLFLUSH 目标 line，再用 MEASURE_LINE 读取延迟。 */
static int measure_clflush_checked(struct hr_reader_ctx *reader, int line,
                                   uint64_t *tsc_out) {
  uint64_t tsc_val = 0;
  if (hr_reader_clflush_line(reader, line) != 0) {
    fprintf(stderr,
            "[HR/cont_cache] ioctl(HPA_READER_IOC_CLFLUSH_LINE) failed: "
            "errno=%d (%s) page_gpa=0x%llx line=%d\n",
            errno, strerror(errno),
            (unsigned long long)(reader ? reader->page_gpa : 0), line);
    return -1;
  }
  if (hr_reader_measure_line(reader, line, &tsc_val) != 0) {
    fprintf(stderr,
            "[HR/cont_cache] ioctl(HPA_READER_IOC_MEASURE_LINE) failed: "
            "errno=%d (%s) page_gpa=0x%llx line=%d\n",
            errno, strerror(errno),
            (unsigned long long)(reader ? reader->page_gpa : 0), line);
    return -1;
  }
  *tsc_out = tsc_val;
  return 0;
}

void *hr_mode_contention_cacheable_impl(void *arg) {
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
  int fatal_error = 0;
  char error_reason[256];
  char done_path[512];
  char hb_path[512];
  FILE *df = NULL;

  error_reason[0] = '\0';
  snprintf(done_path, sizeof(done_path), "%s/contention_done.txt",
           outdir ? outdir : ".");
  snprintf(hb_path, sizeof(hb_path), "%s/contention_heartbeat.txt",
           outdir ? outdir : ".");
  write_heartbeat(hb_path, "init", collected, last_seq, "thread_started");

  (void)arg;
  if (!outdir || !sync_log) {
    fprintf(stderr,
            "[HR/cont_cache] missing env: HR_OUTDIR=%p HR_SYNC_LOG=%p\n",
            (void *)outdir, (void *)sync_log);
    return NULL;
  }
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);

  wait_file_exists(sync_log);
  write_heartbeat(hb_path, "wait_probe_shared_gpa", collected, last_seq,
                  "waiting_sync_log_probe_line");
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
    fprintf(stderr,
            "[HR/cont_cache] wait_probe_shared_gpa failed: sync_log=%s\n",
            sync_log);
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "wait_probe_shared_gpa_failed");
    goto done;
  }
  write_heartbeat(hb_path, "probe_shared_gpa_ok", collected, last_seq,
                  "parsed_shared_gpa");

  maybe_pin_cpu(cpu);
  write_heartbeat(hb_path, "find_vm_fd", collected, last_seq,
                  "search_kvm_vm_fd");
  for (int i = 0; i < 100; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR/cont_cache] find_self_kvm_vm_fd failed\n");
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "find_self_kvm_vm_fd_failed");
    goto done;
  }
  write_heartbeat(hb_path, "find_vm_fd_ok", collected, last_seq, "vm_fd_found");

  write_heartbeat(hb_path, "map_shared_counter", collected, last_seq,
                  "map_shared_counter_page");
  shared_ptr =
      map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, &shared_hpa);
  if (!shared_ptr) {
    fprintf(stderr,
            "[HR/cont_cache] map_shared_counter_page failed: vm_fd=%d "
            "shared_gpa=0x%llx errno=%d (%s)\n",
            vm_fd, (unsigned long long)shared_gpa, errno, strerror(errno));
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "map_shared_counter_page_failed");
    goto done;
  }
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  write_heartbeat(hb_path, "wait_mailbox_magic", collected, last_seq,
                  "waiting_mailbox_magic");
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr, "[HR/cont_cache] mailbox magic timeout\n");
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "mailbox_magic_timeout");
    goto done;
  }
  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  write_heartbeat(hb_path, "wait_guest_cfg", collected, last_guest_seq,
                  "waiting_cfg_ready");
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR/cont_cache] wait_guest_cfg timeout\n");
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "wait_guest_cfg_timeout");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_CONTENTION) {
    fprintf(stderr, "[HR/cont_cache] unexpected cfg_mode=%llu (want CONTENTION=%d)\n",
            (unsigned long long)cfg.mode, (int)SYNC_CFG_MODE_CONTENTION);
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "unexpected_cfg_mode_%llu",
             (unsigned long long)cfg.mode);
    goto done;
  }
  write_heartbeat(hb_path, "cfg_ok", collected, last_guest_seq,
                  "cfg_mode_contention");
  page_gpa = cfg.target_gpa;
  other_gpa = cfg.other_gpa;
  if (hr_reader_open(&page_reader) != 0 ||
      hr_reader_open(&other_reader) != 0) {
    fprintf(stderr, "[HR/cont_cache] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "open_hpa_reader_failed");
    goto done;
  }
  if (hr_reader_bind(&page_reader, vm_fd, page_gpa,
                     HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0) {
    fprintf(stderr,
            "[HR/cont_cache] hr_reader_bind target failed: gpa=0x%llx errno=%d (%s)\n",
            (unsigned long long)page_gpa, errno, strerror(errno));
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "bind_target_reader_failed");
    goto done;
  }
  if (hr_reader_bind(&other_reader, vm_fd, other_gpa,
                     HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0) {
    fprintf(stderr,
            "[HR/cont_cache] hr_reader_bind other failed: gpa=0x%llx errno=%d (%s)\n",
            (unsigned long long)other_gpa, errno, strerror(errno));
    fatal_error = 1;
    snprintf(error_reason, sizeof(error_reason), "bind_other_reader_failed");
    goto done;
  }
  page_hpa = page_reader.page_hpa;
  other_hpa = other_reader.page_hpa;

  if (ensure_dir_p(outdir) != 0)
    fatal_error = 1;
  if (fatal_error) {
    snprintf(error_reason, sizeof(error_reason), "ensure_dir_p_failed");
    goto done;
  }

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

  /* 预热：排空 LLC 中的残留缓存行 */
  {
    const int N_DRAIN = 200;
    write_heartbeat(hb_path, "drain_start", collected, last_guest_seq,
                    "drain_llc_residue");
    for (int i = 0; i < N_DRAIN; i++) {
      uint64_t tmp = 0;
      write_heartbeat(hb_path, "drain_h0_ioctl_enter", collected, last_guest_seq,
                      "measure_clflush_other");
      if (measure_clflush_checked(&other_reader, 0, &tmp) != 0) {
        fatal_error = 1;
        snprintf(error_reason, sizeof(error_reason),
                 "drain_h0_ioctl_failed_iter_%d", i);
        goto done;
      }
      write_heartbeat(hb_path, "drain_h0_ioctl_ok", collected, last_guest_seq,
                      "measure_clflush_other_done");
      uint64_t seq = 0;
      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0) {
        fatal_error = 1;
        snprintf(error_reason, sizeof(error_reason),
                 "drain_wait_sync_timeout_iter_%d", i);
        break;
      }
      write_heartbeat(hb_path, "drain_h1_ioctl_enter", collected, last_guest_seq,
                      "measure_clflush_target");
      if (measure_clflush_checked(&page_reader, 0, &tmp) != 0) {
        fatal_error = 1;
        snprintf(error_reason, sizeof(error_reason),
                 "drain_h1_ioctl_failed_iter_%d", i);
        goto done;
      }
      signal_sync_host_ack(sync_mb, seq);
      last_guest_seq = seq;
      if ((i & 0x0F) == 0)
        write_heartbeat(hb_path, "drain_progress", collected, last_guest_seq,
                        "drain_iter_checkpoint");
    }
    write_heartbeat(hb_path, "drain_done", collected, last_guest_seq,
                    "drain_completed");
  }

  while (collected < reps) {
    uint64_t seq = 0;
    /* H0: 在 guest sync 前测量 other_gpa（guest 不访问该行）*/
    uint64_t c_h0 = 0;
    uint64_t c_h1 = 0;
    write_heartbeat(hb_path, "main_h0_ioctl_enter", collected, last_guest_seq,
                    "measure_h0_other");
    if (measure_clflush_checked(&other_reader, 0, &c_h0) != 0) {
      fatal_error = 1;
      snprintf(error_reason, sizeof(error_reason),
               "main_h0_ioctl_failed_collected_%d", collected);
      goto done;
    }
    if (c_h0 == 0 || c_h0 > 100000)
      c_h0 = 9999;

    write_heartbeat(hb_path, "main_wait_sync", collected, last_guest_seq,
                    "wait_guest_seq");
    if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0) {
      fatal_error = 1;
      snprintf(error_reason, sizeof(error_reason),
               "main_wait_sync_timeout_collected_%d", collected);
      break;
    }

    /* H1: 在 guest sync 后测量 page_gpa（guest 刚完成 CLFLUSH+load）*/
    write_heartbeat(hb_path, "main_h1_ioctl_enter", collected, last_guest_seq,
                    "measure_h1_target");
    if (measure_clflush_checked(&page_reader, 0, &c_h1) != 0) {
      fatal_error = 1;
      snprintf(error_reason, sizeof(error_reason),
               "main_h1_ioctl_failed_collected_%d", collected);
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
    if ((collected & 0xFF) == 0)
      write_heartbeat(hb_path, "main_progress", collected, last_guest_seq,
                      "sample_checkpoint");
  }
  write_heartbeat(hb_path, "main_loop_done", collected, last_guest_seq,
                  "sampling_loop_finished");

  {
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
    meta = fopen(meta_path, "w");
    if (meta) {
      fprintf(meta,
              "mode=contention-cacheable-clflush\n"
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
  }

done:
  hr_reader_close(&page_reader);
  hr_reader_close(&other_reader);
  write_heartbeat(hb_path, fatal_error ? "done_error" : "done_ok", collected,
                  last_seq, error_reason[0] ? error_reason : "none");
  df = fopen(done_path, "w");
  if (df) {
    fprintf(df,
            "status=%s\n"
            "collected=%d\n"
            "mode=contention-cacheable-clflush\n"
            "error_reason=%s\n",
            fatal_error ? "error" : "ok", collected,
            error_reason[0] ? error_reason : "none");
    fclose(df);
  }
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

void *hr_main_thread_contention_cacheable(void *arg) {
  return hr_mode_contention_cacheable_impl(arg);
}
