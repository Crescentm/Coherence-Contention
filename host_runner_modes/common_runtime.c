#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"
#include "../kmod/hpa_reader_ioctl.h"

void maybe_pin_cpu(int cpu) {
  if (cpu >= 0) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET((unsigned)cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);
  }
}

void wait_file_exists(const char *path) {
  while (access(path, F_OK) != 0)
    usleep(100000);
}

static int wait_shared_counter(volatile uint64_t *counter, uint64_t last_val,
                               double timeout_s) {
  struct timespec ts;
  uint64_t deadline_ns;
  uint64_t spin = 0;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  deadline_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec +
                (uint64_t)(timeout_s * 1e9);

  while (__atomic_load_n(counter, __ATOMIC_ACQUIRE) == last_val) {
    __builtin_ia32_pause();
    if ((++spin & 0xFFFFFULL) == 0) {
      clock_gettime(CLOCK_MONOTONIC, &ts);
      if ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec >=
          deadline_ns)
        return -1;
    }
  }
  return 0;
}

void shared_cursor_init(struct shared_cursor *c, volatile uint64_t *ptr) {
  uint64_t v = __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
  c->ptr = ptr;
  c->last_seen = v;
  c->credit = 0;
  c->next_seq = v;
}

int shared_consume(struct shared_cursor *c, double timeout_s,
                   uint64_t *seq_out) {
  while (c->credit == 0) {
    uint64_t cur;
    if (wait_shared_counter(c->ptr, c->last_seen, timeout_s) != 0)
      return -1;

    cur = __atomic_load_n(c->ptr, __ATOMIC_ACQUIRE);
    if (cur < c->last_seen) {
      c->last_seen = cur;
      c->next_seq = cur;
      continue;
    }
    c->credit += (cur - c->last_seen);
    c->last_seen = cur;
  }

  c->credit--;
  c->next_seq++;
  if (seq_out)
    *seq_out = c->next_seq;
  return 0;
}

int wait_sync_guest_seq(volatile struct sync_mailbox *mb, uint64_t last_seen,
                        double timeout_s, uint64_t *seq_out) {
  uint64_t cur;

  if (wait_shared_counter(&mb->guest_seq, last_seen, timeout_s) != 0)
    return -1;
  cur = __atomic_load_n((const uint64_t *)&mb->guest_seq, __ATOMIC_ACQUIRE);
  if (seq_out)
    *seq_out = cur;
  return 0;
}

void signal_sync_host_ack(volatile struct sync_mailbox *mb, uint64_t seq) {
  __atomic_store_n((uint64_t *)&mb->host_seq, seq, __ATOMIC_RELEASE);
}

int wait_phase_guest_seq(volatile struct sync_mailbox *mb, uint64_t last_seen,
                         double timeout_s, uint64_t *seq_out) {
  uint64_t cur;

  if (wait_shared_counter(&mb->phase_seq, last_seen, timeout_s) != 0)
    return -1;
  cur = __atomic_load_n((const uint64_t *)&mb->phase_seq, __ATOMIC_ACQUIRE);
  if (seq_out)
    *seq_out = cur;
  return 0;
}

void signal_phase_host_ack(volatile struct sync_mailbox *mb, uint64_t seq) {
  __atomic_store_n((uint64_t *)&mb->phase_ack, seq, __ATOMIC_RELEASE);
}

int wait_mailbox_magic(volatile struct sync_mailbox *mb, double timeout_s) {
  struct timespec ts;
  uint64_t deadline_ns;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  deadline_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec +
                (uint64_t)(timeout_s * 1e9);

  while (__atomic_load_n((const uint64_t *)&mb->phase_magic,
                         __ATOMIC_ACQUIRE) != SYNC_MAILBOX_MAGIC) {
    __builtin_ia32_pause();
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec >=
        deadline_ns)
      return -1;
    usleep(50);
  }
  return 0;
}

int wait_guest_cfg(volatile struct sync_mailbox *mb, uint64_t last_seen,
                   double timeout_s, struct sync_cfg_snapshot *cfg_out) {
  uint64_t seq;
  if (wait_shared_counter(&mb->cfg_ready_seq, last_seen, timeout_s) != 0)
    return -1;

  seq = __atomic_load_n((const uint64_t *)&mb->cfg_ready_seq, __ATOMIC_ACQUIRE);
  if (cfg_out) {
    cfg_out->seq = seq;
    cfg_out->mode =
        __atomic_load_n((const uint64_t *)&mb->cfg_mode, __ATOMIC_ACQUIRE);
    cfg_out->target_gpa = __atomic_load_n((const uint64_t *)&mb->cfg_target_gpa,
                                          __ATOMIC_ACQUIRE);
    cfg_out->other_gpa = __atomic_load_n((const uint64_t *)&mb->cfg_other_gpa,
                                         __ATOMIC_ACQUIRE);
    cfg_out->page_gpa = __atomic_load_n((const uint64_t *)&mb->cfg_page_gpa,
                                        __ATOMIC_ACQUIRE);
    cfg_out->shared_gpa = __atomic_load_n((const uint64_t *)&mb->cfg_shared_gpa,
                                          __ATOMIC_ACQUIRE);
    cfg_out->dec_line = __atomic_load_n((const uint64_t *)&mb->cfg_dec_line,
                                        __ATOMIC_ACQUIRE);
    cfg_out->flags =
        __atomic_load_n((const uint64_t *)&mb->cfg_flags, __ATOMIC_ACQUIRE);
    cfg_out->host_lines = __atomic_load_n((const uint64_t *)&mb->cfg_host_lines,
                                          __ATOMIC_ACQUIRE);
    cfg_out->reps =
        __atomic_load_n((const uint64_t *)&mb->cfg_reps, __ATOMIC_ACQUIRE);
    cfg_out->aux0 =
        __atomic_load_n((const uint64_t *)&mb->cfg_aux0, __ATOMIC_ACQUIRE);
    cfg_out->aux1 =
        __atomic_load_n((const uint64_t *)&mb->cfg_aux1, __ATOMIC_ACQUIRE);
  }

  __atomic_store_n((uint64_t *)&mb->cfg_ack_seq, seq, __ATOMIC_RELEASE);
  return 0;
}

int find_self_kvm_vm_fd(void) {
  DIR *dp;
  struct dirent *de;
  int found = -1;

  dp = opendir("/proc/self/fd");
  if (!dp)
    return -1;

  while ((de = readdir(dp)) != NULL) {
    char link_path[512], target[512];
    ssize_t len;
    if (de->d_name[0] == '.')
      continue;

    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", de->d_name);
    len = readlink(link_path, target, sizeof(target) - 1);
    if (len <= 0)
      continue;
    target[len] = '\0';
    if (strstr(target, "kvm-vm") != NULL) {
      found = atoi(de->d_name);
      break;
    }
  }
  closedir(dp);
  return found;
}

int translate_gpa_to_hpa(int vm_fd, uint64_t gpa, uint64_t *hpa_out) {
  struct kvm_amd_gpa_to_hpa p;
  memset(&p, 0, sizeof(p));
  p.gpa = gpa & ~(PAGE_SZ - 1ULL);

  if (ioctl(vm_fd, KVM_AMD_GPA_TO_HPA, &p) != 0)
    return -1;
  if (p.ret != 0)
    return -1;
  *hpa_out = p.hpa & ~(PAGE_SZ - 1ULL);
  return 0;
}

volatile uint64_t *map_shared_counter_page(int vm_fd, uint64_t shared_gpa,
                                           int *dev_fd_out,
                                           uint64_t *shared_hpa_out) {
  struct kvm_amd_gpa_to_hpa p;
  uint64_t shared_hpa = 0;
  uint64_t shared_hva = 0;
  int fd = -1;
  void *m = MAP_FAILED;

  memset(&p, 0, sizeof(p));
  p.gpa = shared_gpa & ~(PAGE_SZ - 1ULL);
  if (ioctl(vm_fd, KVM_AMD_GPA_TO_HPA, &p) != 0)
    return NULL;
  if (p.ret != 0)
    return NULL;
  shared_hpa = p.hpa & ~(PAGE_SZ - 1ULL);
  shared_hva = p.hva & ~(PAGE_SZ - 1ULL);

  /* In preload mode we run inside QEMU process; prefer direct HVA mapping.
   * This avoids /dev/hpa_reader aliasing and keeps mailbox access coherent. */
  if (shared_hva != 0) {
    if (dev_fd_out)
      *dev_fd_out = -1;
    if (shared_hpa_out)
      *shared_hpa_out = shared_hpa;
    return (volatile uint64_t *)(uintptr_t)shared_hva;
  }

  fd = open(HPA_READER_DEV, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    return NULL;

  if (ioctl(fd, HPA_READER_IOC_SET_SHARED_PAGE, &shared_hpa) != 0) {
    close(fd);
    return NULL;
  }

  m = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) {
    close(fd);
    return NULL;
  }

  if (dev_fd_out)
    *dev_fd_out = fd;
  if (shared_hpa_out)
    *shared_hpa_out = shared_hpa;
  return (volatile uint64_t *)m;
}

uint32_t hr_probe_mode_to_reader_mode(uint32_t probe_mode) {
  switch (probe_mode) {
  case KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE:
    return HPA_READER_MODE_CIPHERTEXT;
  case KVM_AMD_READ_GPA_MODE_CIPHERTEXT_CACHEABLE:
    return HPA_READER_MODE_CIPHERTEXT_CACHEABLE;
  default:
    return UINT32_MAX;
  }
}

int hr_reader_open(struct hr_reader_ctx *ctx) {
  if (!ctx)
    return -1;
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = open(HPA_READER_DEV, O_RDWR | O_CLOEXEC);
  if (ctx->fd < 0)
    return -1;
  return 0;
}

int hr_reader_bind(struct hr_reader_ctx *ctx, int vm_fd, uint64_t page_gpa,
                   uint32_t mode) {
  struct hpa_reader_set_page_req req;

  if (!ctx || ctx->fd < 0)
    return -1;
  page_gpa &= ~(PAGE_SZ - 1ULL);
  if (ctx->is_bound && ctx->page_gpa == page_gpa && ctx->mode == mode)
    return 0;
  if (translate_gpa_to_hpa(vm_fd, page_gpa, &ctx->page_hpa) != 0)
    return -1;

  memset(&req, 0, sizeof(req));
  req.page_hpa = ctx->page_hpa;
  req.mode = mode;
  if (ioctl(ctx->fd, HPA_READER_IOC_SET_PAGE, &req) != 0)
    return -1;

  ctx->page_gpa = page_gpa;
  ctx->mode = mode;
  ctx->is_bound = 1;
  return 0;
}

int hr_reader_measure_line(struct hr_reader_ctx *ctx, int line,
                           uint64_t *cycles_out) {
  struct hpa_reader_measure_req req;

  if (!ctx || ctx->fd < 0 || !ctx->is_bound || line < 0 || line >= (int)LINES)
    return -1;

  memset(&req, 0, sizeof(req));
  req.line = (uint32_t)line;
  if (ioctl(ctx->fd, HPA_READER_IOC_MEASURE_LINE, &req) != 0)
    return -1;
  if (cycles_out)
    *cycles_out = req.cycles;
  return 0;
}

int hr_reader_clflush_line(struct hr_reader_ctx *ctx, int line) {
  struct hpa_reader_line_req req;

  if (!ctx || ctx->fd < 0 || !ctx->is_bound || line < 0 || line >= (int)LINES)
    return -1;

  memset(&req, 0, sizeof(req));
  req.line = (uint32_t)line;
  if (ioctl(ctx->fd, HPA_READER_IOC_CLFLUSH_LINE, &req) != 0)
    return -1;
  return 0;
}

void hr_reader_close(struct hr_reader_ctx *ctx) {
  if (!ctx || ctx->fd < 0)
    return;
  (void)ioctl(ctx->fd, HPA_READER_IOC_CLEAR_PAGE);
  close(ctx->fd);
  ctx->fd = -1;
  ctx->page_gpa = 0;
  ctx->page_hpa = 0;
  ctx->mode = 0;
  ctx->is_bound = 0;
}

uint64_t measure_line_ex(int vm_fd, uint64_t page_gpa, int line,
                         uint32_t mode) {
  return measure_line_ex_flags(vm_fd, page_gpa, line, mode, 0, NULL);
}

uint64_t measure_line_ex_flags(int vm_fd, uint64_t page_gpa, int line,
                               uint32_t mode, uint64_t flags,
                               uint32_t *resolved_mode_out) {
  static __attribute__((aligned(64))) uint8_t buf[LINE_SZ];
  struct kvm_amd_read_gpa p;
  memset(&p, 0, sizeof(p));
  p.gpa = page_gpa + (uint64_t)line * LINE_SZ;
  p.user_buf = (uint64_t)(uintptr_t)buf;
  p.size = LINE_SZ;
  p.mode = mode;
  p.flags = flags;

  if (ioctl(vm_fd, KVM_AMD_READ_GPA, &p) != 0)
    return 0;
  if (p.ret != 0)
    return 0;
  if (resolved_mode_out)
    *resolved_mode_out = p.mode;
  return p.tsc_delta;
}

static int ensure_dir(const char *path) {
  struct stat st;
  if (stat(path, &st) == 0)
    return S_ISDIR(st.st_mode) ? 0 : -1;
  return mkdir(path, 0755);
}

int ensure_dir_p(const char *path) {
  char tmp[512];
  size_t len;

  if (!path || !*path)
    return -1;
  len = strnlen(path, sizeof(tmp) - 1);
  if (len == 0 || len >= sizeof(tmp))
    return -1;

  memcpy(tmp, path, len);
  tmp[len] = '\0';

  for (char *p = tmp + 1; *p; ++p) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (ensure_dir(tmp) != 0 && errno != EEXIST)
      return -1;
    *p = '/';
  }
  if (ensure_dir(tmp) != 0 && errno != EEXIST)
    return -1;
  return 0;
}

static int wait_next_log_line(const char *log_path, uint64_t *off, char *buf,
                              size_t buf_sz, double timeout_s) {
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

static int parse_u64_after_key_fmt(const char *line, const char *key,
                                   uint64_t *out, const char *fmt) {
  const char *p = strstr(line, key);
  unsigned long long v = 0;
  if (!p)
    return -1;
  if (sscanf(p + strlen(key), fmt, &v) != 1)
    return -1;
  *out = (uint64_t)v;
  return 0;
}

static int parse_hex_after_key(const char *line, const char *key,
                               uint64_t *out) {
  return parse_u64_after_key_fmt(line, key, out, "%llx");
}

int wait_probe_shared_gpa(const char *sync_log, uint64_t *off,
                          uint64_t *shared_gpa) {
  const int max_timeouts = 30; /* 30 * 60s = up to 30 minutes */
  int timeout_count = 0;
  char line[512];
  for (;;) {
    if (wait_next_log_line(sync_log, off, line, sizeof(line), 60.0) != 0) {
      timeout_count++;
      if (timeout_count >= max_timeouts) {
        fprintf(stderr,
                "[HR/runtime] wait_probe_shared_gpa timeout: sync_log=%s "
                "off=%llu retries=%d\n",
                sync_log ? sync_log : "(null)", (unsigned long long)(off ? *off : 0ULL),
                timeout_count);
        return -1;
      }
      fprintf(stderr,
              "[HR/runtime] wait_probe_shared_gpa timeout, retry %d/%d "
              "(sync_log=%s off=%llu)\n",
              timeout_count, max_timeouts, sync_log ? sync_log : "(null)",
              (unsigned long long)(off ? *off : 0ULL));
      continue;
    }
    timeout_count = 0;
    if (strstr(line, "SNP_PROBE ") == NULL)
      continue;
    if (parse_hex_after_key(line, "shared_gpa=0x", shared_gpa) != 0)
      continue;
    return 0;
  }
}
