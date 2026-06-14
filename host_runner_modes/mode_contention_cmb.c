#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

/*
 * mode_contention_cmb — 实验 4.2.4 H1_cmb
 *
 * 一致性 + 竞争联合信号：
 *   - 使用 CIPHERTEXT_CACHEABLE（无 clflush），保留一致性信号
 *   - guest 以 contention_blind 模式运行（CLFLUSH+load 紧循环，无同步），
 *     同时提供竞争信号
 *   - 宿主机盲探测（不等 guest sync），与 mode_blind 类似
 *
 * H0: 测量 other_gpa（guest 不访问该行）
 * H1: 测量 page_gpa（guest 持续 CLFLUSH+load）
 *
 * 等待 sync_log 中出现 SNP_PROBE CONTENTION_BLIND 行。
 */

static int wait_next_log_line_cmb(const char *log_path, uint64_t *off,
                                  char *buf, size_t buf_sz, double timeout_s) {
  struct timespec ts;
  uint64_t deadline_ns;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  deadline_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec +
                (uint64_t)(timeout_s * 1e9);
  for (;;) {
    int fd = open(log_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = pread(fd, buf, buf_sz - 1, (off_t)*off);
      close(fd);
      if (n > 0) {
        char *nl;
        buf[n] = '\0';
        nl = strchr(buf, '\n');
        if (nl) {
          *nl = '\0';
          *off += (uint64_t)(nl - buf) + 1ULL;
          return 0;
        }
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec >=
        deadline_ns)
      return -1;
    usleep(50);
  }
}

static int parse_hex_cmb(const char *line, const char *key, uint64_t *out) {
  const char *p = strstr(line, key);
  unsigned long long v = 0;
  if (!p)
    return -1;
  if (sscanf(p + strlen(key), "%llx", &v) != 1)
    return -1;
  *out = (uint64_t)v;
  return 0;
}

static int wait_contention_blind(const char *sync_log, uint64_t *off,
                                 uint64_t *target_gpa,
                                 uint64_t *other_page_gpa) {
  char line[512];
  for (;;) {
    if (wait_next_log_line_cmb(sync_log, off, line, sizeof(line), 60.0) != 0)
      return -1;
    if (strstr(line, "SNP_PROBE CONTENTION_BLIND") == NULL)
      continue;
    if (parse_hex_cmb(line, "target_gpa=0x", target_gpa) != 0)
      continue;
    if (parse_hex_cmb(line, "other_page_gpa=0x", other_page_gpa) != 0)
      continue;
    return 0;
  }
}

void *hr_mode_contention_cmb_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 20000;
  int cpu = -1;
  int victim_line = 0;
  uint64_t target_gpa = 0, other_gpa = 0;
  uint64_t log_off = 0;
  int vm_fd = -1;
  FILE *fh1 = NULL, *fh0 = NULL, *meta = NULL;
  uint64_t target_hpa = 0;
  unsigned raw_pending = 0;
  struct hr_reader_ctx target_reader = {.fd = -1};
  struct hr_reader_ctx other_reader = {.fd = -1};

  (void)arg;
  if (!outdir || !sync_log)
    return NULL;
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);
  if ((env = getenv("HR_VICTIM_LINE")))
    victim_line = atoi(env);

  wait_file_exists(sync_log);
  if (wait_contention_blind(sync_log, &log_off, &target_gpa, &other_gpa) != 0)
    return NULL;

  maybe_pin_cpu(cpu);
  for (int i = 0; i < 50; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0)
    return NULL;

  if (hr_reader_open(&target_reader) != 0 ||
      hr_reader_open(&other_reader) != 0) {
    fprintf(stderr, "[HR/cont_cmb] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    goto done;
  }
  if (hr_reader_bind(&target_reader, vm_fd, target_gpa,
                     HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0 ||
      hr_reader_bind(&other_reader, vm_fd, other_gpa,
                     HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0) {
    fprintf(stderr,
            "[HR/cont_cmb] hr_reader_bind failed: target_gpa=0x%llx other_gpa=0x%llx errno=%d (%s)\n",
            (unsigned long long)target_gpa, (unsigned long long)other_gpa,
            errno, strerror(errno));
    goto done;
  }
  target_hpa = target_reader.page_hpa;

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

  /* 预热 */
  for (int i = 0; i < 200; i++) {
    uint64_t warm = 0;
    (void)hr_reader_measure_line(&target_reader, victim_line, &warm);
    (void)hr_reader_measure_line(&other_reader, victim_line, &warm);
  }

  for (int rep = 0; rep < reps; rep++) {
    /* H0: other page（guest 不访问）*/
    uint64_t c_h0 = 0;
    if (hr_reader_measure_line(&other_reader, victim_line, &c_h0) != 0) {
      fprintf(stderr, "[HR/cont_cmb] H0 measure failed: errno=%d (%s)\n",
              errno, strerror(errno));
      goto done;
    }
    if (c_h0 == 0)
      c_h0 = 9999;
    /* H1: target page（guest 持续 CLFLUSH+load）*/
    uint64_t c_h1 = 0;
    if (hr_reader_measure_line(&target_reader, victim_line, &c_h1) != 0) {
      fprintf(stderr, "[HR/cont_cmb] H1 measure failed: errno=%d (%s)\n",
              errno, strerror(errno));
      goto done;
    }
    if (c_h1 == 0)
      c_h1 = 9999;

    fprintf(fh0, "%llu\n", (unsigned long long)c_h0);
    fprintf(fh1, "%llu\n", (unsigned long long)c_h1);
    if (++raw_pending >= 256) {
      fflush(fh0);
      fflush(fh1);
      raw_pending = 0;
    }
  }
  if (raw_pending > 0) {
    fflush(fh0);
    fflush(fh1);
  }

  {
    char meta_path[512], done_path[512];
    FILE *df;
    snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
    meta = fopen(meta_path, "w");
    if (meta) {
      fprintf(meta,
              "mode=contention-cmb-cacheable\n"
              "target_gpa=0x%llx\n"
              "target_hpa=0x%llx\n"
              "victim_line=%d\n"
              "reps=%d\n",
              (unsigned long long)target_gpa, (unsigned long long)target_hpa,
              victim_line, reps);
    }
    snprintf(done_path, sizeof(done_path), "%s/contention_done.txt", outdir);
    df = fopen(done_path, "w");
    if (df) {
      fprintf(df, "collected=%d\nmode=contention-cmb-cacheable\n", reps);
      fclose(df);
    }
  }

done:
  hr_reader_close(&target_reader);
  hr_reader_close(&other_reader);
  if (fh1)
    fclose(fh1);
  if (fh0)
    fclose(fh0);
  if (meta)
    fclose(meta);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_contention_cmb(void *arg) {
  return hr_mode_contention_cmb_impl(arg);
}
