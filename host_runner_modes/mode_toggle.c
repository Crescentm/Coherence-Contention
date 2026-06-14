#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"
#include "../kmod/hpa_reader_ioctl.h"

struct toggle_event {
  uint64_t seq;
  char state;
  uint32_t fill;
};

struct toggle_mode_diag {
  const char *name;
  uint32_t mode;
  uint64_t fp_a;
  uint64_t fp_b;
  int have_a;
  int have_b;
  int mismatches;
};

static int parse_u64_after_key_local(const char *line, const char *key,
                                     uint64_t *out) {
  const char *p = strstr(line, key);
  unsigned long long v = 0;
  if (!p)
    return -1;
  if (sscanf(p + strlen(key), "%llu", &v) != 1)
    return -1;
  *out = (uint64_t)v;
  return 0;
}

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

static int wait_toggle_event_local(const char *sync_log, uint64_t *off,
                                   struct toggle_event *ev,
                                   double timeout_s) {
  char line[512];
  uint64_t seq = 0;
  unsigned fill = 0;
  char state = '\0';

  for (;;) {
    if (wait_next_log_line_local(sync_log, off, line, sizeof(line),
                                 timeout_s) != 0)
      return -1;
    if (strstr(line, "SNP_TOGGLE_DONE") != NULL)
      return 1;
    if (strstr(line, "SNP_TOGGLE ") == NULL)
      continue;
    if (parse_u64_after_key_local(line, "seq=", &seq) != 0)
      continue;
    if (sscanf(strstr(line, "state="), "state=%c", &state) != 1)
      continue;
    if (sscanf(strstr(line, "fill=0x"), "fill=0x%x", &fill) != 1)
      fill = 0;
    ev->seq = seq;
    ev->state = state;
    ev->fill = fill;
    return 0;
  }
}

static int hpa_reader_read_local(int fd, uint64_t hpa, uint32_t mode,
                                 uint8_t *buf, uint32_t size) {
  struct hpa_reader_req req;
  memset(&req, 0, sizeof(req));
  req.hpa = hpa;
  req.size = size;
  req.mode = mode;
  if (ioctl(fd, HPA_READER_IOC_READ, &req) != 0)
    return -1;
  memcpy(buf, req.data, size);
  return 0;
}

static uint64_t fnv1a64_bytes_local(const uint8_t *buf, size_t n) {
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint64_t)buf[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static void bytes_to_hex16_local(const uint8_t *buf, char *out, size_t out_sz) {
  static const char *hex = "0123456789abcdef";
  size_t n = 16;
  if (out_sz < n * 2 + 1) {
    if (out_sz)
      out[0] = '\0';
    return;
  }
  for (size_t i = 0; i < n; i++) {
    out[i * 2] = hex[(buf[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[buf[i] & 0xF];
  }
  out[n * 2] = '\0';
}

static void toggle_mode_record_local(struct toggle_mode_diag *d, char state,
                                     uint64_t fp) {
  if (state == 'A') {
    if (!d->have_a) {
      d->fp_a = fp;
      d->have_a = 1;
    } else if (d->fp_a != fp) {
      d->mismatches++;
    }
  } else if (state == 'B') {
    if (!d->have_b) {
      d->fp_b = fp;
      d->have_b = 1;
    } else if (d->fp_b != fp) {
      d->mismatches++;
    }
  }
}

static int toggle_mode_ok_local(const struct toggle_mode_diag *d) {
  return d->have_a && d->have_b && d->fp_a != d->fp_b && d->mismatches == 0;
}

void *hr_mode_toggle_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int cpu = -1;
  int vm_fd = -1;
  int shared_fd = -1;
  int reader_fd = -1;
  uint64_t log_off = 0;
  uint64_t page_gpa = 0, line_gpa = 0, line_off = 0, shared_gpa = 0;
  uint64_t last_cfg_seq = 0;
  uint64_t page_hpa = 0, line_hpa = 0;
  uint64_t iters = 0, delay_us = 0;
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  int line = 0;
  char flush_mode[32] = {0};
  FILE *trace = NULL, *summary = NULL, *done = NULL;
  int events = 0, transitions = 0, hpa_mismatches = 0;
  int prev_valid = 0;
  uint64_t prev_fp = 0;
  char trace_path[512], summary_path[512], done_path[512];
  struct toggle_mode_diag modes[] = {
      {.name = "hostdec", .mode = HPA_READER_MODE_HOSTDEC},
      {.name = "ciphertext", .mode = HPA_READER_MODE_CIPHERTEXT},
      {.name = "hostdec_cacheable", .mode = HPA_READER_MODE_HOSTDEC_CACHEABLE},
      {.name = "ciphertext_cacheable",
       .mode = HPA_READER_MODE_CIPHERTEXT_CACHEABLE},
  };

  (void)arg;
  if (!outdir || !sync_log)
    return NULL;
  if ((env = getenv("HR_CPU")))
    cpu = atoi(env);

  wait_file_exists(sync_log);
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0) {
    fprintf(stderr, "[HR-TGL] failed to parse shared_gpa\n");
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
    fprintf(stderr, "[HR-TGL] vm_fd not found\n");
    return NULL;
  }

  shared_ptr = map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, NULL);
  if (!shared_ptr) {
    fprintf(stderr, "[HR-TGL] map_shared_counter_page failed\n");
    return NULL;
  }
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr, "[HR-TGL] mailbox magic timeout\n");
    goto done;
  }
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR-TGL] wait_guest_cfg timeout\n");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_TOGGLE) {
    fprintf(stderr, "[HR-TGL] unexpected cfg_mode=%llu\n",
            (unsigned long long)cfg.mode);
    goto done;
  }
  page_gpa = cfg.page_gpa;
  line_gpa = cfg.target_gpa;
  line = (int)cfg.dec_line;
  iters = cfg.reps;
  delay_us = cfg.aux0;
  strncpy(flush_mode, "shared_cfg", sizeof(flush_mode) - 1);
  flush_mode[sizeof(flush_mode) - 1] = '\0';

  if (translate_gpa_to_hpa(vm_fd, page_gpa, &page_hpa) != 0) {
    fprintf(stderr,
            "[HR-TGL] translate_gpa_to_hpa failed for page_gpa=0x%llx\n",
            (unsigned long long)page_gpa);
    goto done;
  }
  line_off = line_gpa - page_gpa;
  line_hpa = page_hpa + line_off;

  reader_fd = open(HPA_READER_DEV, O_RDWR | O_CLOEXEC);
  if (reader_fd < 0) {
    fprintf(stderr, "[HR-TGL] open %s failed: %s\n", HPA_READER_DEV,
            strerror(errno));
    goto done;
  }

  if (ensure_dir_p(outdir) != 0)
    goto done;

  snprintf(trace_path, sizeof(trace_path), "%s/toggle_trace.csv", outdir);
  snprintf(summary_path, sizeof(summary_path), "%s/toggle_summary.txt", outdir);
  snprintf(done_path, sizeof(done_path), "%s/toggle_done.txt", outdir);
  trace = fopen(trace_path, "w");
  summary = fopen(summary_path, "w");
  if (!trace || !summary)
    goto done;

  fprintf(trace,
          "seq,state,fill,tsc_delta,resolved_hpa,fp_hostdec,head16_hostdec,"
          "fp_ciphertext,head16_ciphertext,fp_hostdec_cacheable,"
          "head16_hostdec_cacheable,fp_ciphertext_cacheable,"
          "head16_ciphertext_cacheable\n");

  for (;;) {
    struct toggle_event ev;
    int rc = wait_toggle_event_local(sync_log, &log_off, &ev, 120.0);
    if (rc == 1)
      break;
    if (rc != 0)
      break;

    uint8_t buf[4][HPA_READER_MAX_BYTES];
    uint64_t fp[4] = {0};
    char hex[4][33];

    for (int i = 0; i < 4; i++) {
      if (hpa_reader_read_local(reader_fd, line_hpa, modes[i].mode, buf[i],
                                64) != 0) {
        memset(buf[i], 0, 64);
        hpa_mismatches++;
      }
      fp[i] = fnv1a64_bytes_local(buf[i], 64);
      bytes_to_hex16_local(buf[i], hex[i], sizeof(hex[i]));
      toggle_mode_record_local(&modes[i], ev.state, fp[i]);
    }

    if (prev_valid && prev_fp != fp[3])
      transitions++;
    prev_fp = fp[3];
    prev_valid = 1;
    events++;

    fprintf(trace,
            "%llu,%c,0x%02x,%llu,0x%llx,0x%016llx,%s,0x%016llx,%s,"
            "0x%016llx,%s,0x%016llx,%s\n",
            (unsigned long long)ev.seq, ev.state, ev.fill,
            (unsigned long long)delay_us, (unsigned long long)line_hpa,
            (unsigned long long)fp[0], hex[0], (unsigned long long)fp[1],
            hex[1], (unsigned long long)fp[2], hex[2],
            (unsigned long long)fp[3], hex[3]);
    fflush(trace);
  }

  fprintf(summary, "line=%d\n", line);
  fprintf(summary, "line_gpa=0x%llx\n", (unsigned long long)line_gpa);
  fprintf(summary, "page_hpa=0x%llx\n", (unsigned long long)page_hpa);
  fprintf(summary, "iters=%llu\n", (unsigned long long)iters);
  fprintf(summary, "delay_us=%llu\n", (unsigned long long)delay_us);
  fprintf(summary, "flush=%s\n", flush_mode);
  fprintf(summary, "events=%d\n", events);
  fprintf(summary, "transitions=%d\n", transitions);
  fprintf(summary, "reader=module\n");
  fprintf(summary, "hpa_mismatches=%d\n", hpa_mismatches);
  fprintf(summary, "fingerprint_A=0x%016llx\n",
          (unsigned long long)modes[3].fp_a);
  fprintf(summary, "fingerprint_B=0x%016llx\n",
          (unsigned long long)modes[3].fp_b);
  fprintf(summary, "toggles_ok=%d\n", toggle_mode_ok_local(&modes[3]));
  fprintf(summary, "mismatches=%d\n", modes[3].mismatches);
  for (int i = 0; i < 4; i++) {
    fprintf(summary, "mode_%s_fingerprint_A=0x%016llx\n", modes[i].name,
            (unsigned long long)modes[i].fp_a);
    fprintf(summary, "mode_%s_fingerprint_B=0x%016llx\n", modes[i].name,
            (unsigned long long)modes[i].fp_b);
    fprintf(summary, "mode_%s_toggles_ok=%d\n", modes[i].name,
            toggle_mode_ok_local(&modes[i]));
    fprintf(summary, "mode_%s_mismatches=%d\n", modes[i].name,
            modes[i].mismatches);
  }
  {
    int any_ok = 0;
    for (int i = 0; i < 4; i++)
      any_ok |= toggle_mode_ok_local(&modes[i]);
    fprintf(summary, "toggles_any_mode=%d\n", any_ok);
    fflush(summary);
    done = fopen(done_path, "w");
    if (done) {
      fprintf(done, "events=%d toggles_ok=%d\n", events, any_ok);
      fflush(done);
    }
  }

done:
  if (trace)
    fclose(trace);
  if (summary)
    fclose(summary);
  if (done)
    fclose(done);
  if (shared_ptr && shared_fd >= 0)
    munmap((void *)shared_ptr, PAGE_SZ);
  if (shared_fd >= 0)
    close(shared_fd);
  if (reader_fd >= 0)
    close(reader_fd);
  return NULL;
}

void *hr_main_thread_toggle(void *arg) { return hr_mode_toggle_impl(arg); }
