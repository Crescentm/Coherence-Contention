#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <openssl/aes.h>

#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t rdtscp64(void) {
  unsigned aux = 0;
  return __rdtscp(&aux);
}
#else
static inline uint64_t rdtscp64(void) { return 0; }
#endif

#ifdef __has_include
#if __has_include(<linux/perf_event.h>)
#include <linux/perf_event.h>
#endif
#endif

#ifndef PERF_TYPE_HARDWARE
#define PERF_TYPE_HARDWARE 0
#endif
#ifndef PERF_COUNT_HW_CACHE_MISSES
#define PERF_COUNT_HW_CACHE_MISSES 3
#endif
#ifndef PERF_EVENT_IOC_ENABLE
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#endif
#ifndef PERF_EVENT_IOC_DISABLE
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)
#endif
#ifndef PERF_EVENT_IOC_RESET
#define PERF_EVENT_IOC_RESET _IO('$', 3)
#endif

#ifndef PERF_ATTR_SIZE_VER0
#define PERF_ATTR_SIZE_VER0 64
struct perf_event_attr {
  uint32_t type;
  uint32_t size;
  uint64_t config;
  union {
    uint64_t sample_period;
    uint64_t sample_freq;
  };
  uint64_t sample_type;
  uint64_t read_format;
  uint64_t disabled : 1;
  uint64_t inherit : 1;
  uint64_t pinned : 1;
  uint64_t exclusive : 1;
  uint64_t exclude_user : 1;
  uint64_t exclude_kernel : 1;
  uint64_t exclude_hv : 1;
  uint64_t exclude_idle : 1;
  uint64_t mmap : 1;
  uint64_t comm : 1;
  uint64_t freq : 1;
  uint64_t inherit_stat : 1;
  uint64_t enable_on_exec : 1;
  uint64_t task : 1;
  uint64_t watermark : 1;
  uint64_t precise_ip : 2;
  uint64_t mmap_data : 1;
  uint64_t sample_id_all : 1;
  uint64_t exclude_host : 1;
  uint64_t exclude_guest : 1;
  uint64_t exclude_callchain_kernel : 1;
  uint64_t exclude_callchain_user : 1;
  uint64_t mmap2 : 1;
  uint64_t comm_exec : 1;
  uint64_t use_clockid : 1;
  uint64_t context_switch : 1;
  uint64_t write_backward : 1;
  uint64_t namespaces : 1;
  uint64_t __reserved_1 : 35;
  union {
    uint32_t wakeup_events;
    uint32_t wakeup_watermark;
  };
  uint32_t bp_type;
  union {
    uint64_t bp_addr;
    uint64_t config1;
  };
  union {
    uint64_t bp_len;
    uint64_t config2;
  };
  uint64_t branch_sample_type;
  uint64_t sample_regs_user;
  uint32_t sample_stack_user;
  int32_t clockid;
  uint64_t sample_regs_intr;
  uint32_t aux_watermark;
  uint16_t sample_max_stack;
  uint16_t __reserved_2;
  uint32_t aux_sample_size;
  uint32_t __reserved_3;
  uint64_t sig_data;
};
#endif

#ifndef SYS_perf_event_open
#ifdef __NR_perf_event_open
#define SYS_perf_event_open __NR_perf_event_open
#endif
#endif

static volatile uint8_t g_sink = 0;

static int perf_event_open_local(struct perf_event_attr *attr, pid_t pid, int cpu,
                                 int group_fd, unsigned long flags) {
#ifdef SYS_perf_event_open
  return (int)syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
#else
  (void)attr;
  (void)pid;
  (void)cpu;
  (void)group_fd;
  (void)flags;
  errno = ENOSYS;
  return -1;
#endif
}

static int open_cache_miss_counter(int *open_errno) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CACHE_MISSES;
  attr.disabled = 1;
  /*
   * Paper-facing metric: count user-space misses for the benchmark body.
   * Exclude kernel/hypervisor noise in PMU accounting.
   */
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  {
    int fd = perf_event_open_local(&attr, 0, -1, -1, 0);
    if (fd < 0 && errno == E2BIG) {
      /* Kernel may return E2BIG and overwrite attr.size with expected size. */
      uint32_t ksz = attr.size;
      if (ksz >= PERF_ATTR_SIZE_VER0 && ksz < sizeof(attr)) {
        attr.size = ksz;
        fd = perf_event_open_local(&attr, 0, -1, -1, 0);
      }
    }
    if (fd < 0 && open_errno)
      *open_errno = errno;
    return fd;
  }
}

int main(int argc, char **argv) {
  enum { REPEATS = 9 };
  size_t blocks = 5000000;
  uint8_t key[16];
  uint8_t in[16];
  uint8_t out[16];
  AES_KEY aes_key;
  double misses_total = 0.0;
  int valid = 0;
  int r;
  int perf_open_errno = 0;
  int perf_reset_errno = 0;
  int perf_enable_errno = 0;
  int perf_read_errno = 0;
  if (argc >= 2) {
    char *end = NULL;
    unsigned long long v = strtoull(argv[1], &end, 10);
    if (end && *end == '\0' && v > 0)
      blocks = (size_t)v;
  }

  for (int i = 0; i < 16; i++) {
    key[i] = (uint8_t)(i * 13 + 7);
    in[i] = (uint8_t)(i * 17 + 3);
  }
  if (AES_set_encrypt_key(key, 128, &aes_key) != 0)
    return 1;

  for (r = 0; r < REPEATS; r++) {
    int fd = open_cache_miss_counter(&perf_open_errno);
    uint64_t misses = 0;
    ssize_t nread;
    if (fd < 0)
      continue;
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0) {
      if (!perf_reset_errno)
        perf_reset_errno = errno;
      close(fd);
      continue;
    }
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
      if (!perf_enable_errno)
        perf_enable_errno = errno;
      close(fd);
      continue;
    }

    for (size_t i = 0; i < blocks; i++) {
      AES_encrypt(in, out, &aes_key);
      in[(i + out[0]) & 0xF] ^= out[(i + 7) & 0xF];
      g_sink ^= out[i & 0xF];
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    nread = read(fd, &misses, sizeof(misses));
    if (nread == (ssize_t)sizeof(misses)) {
      misses_total += (double)misses;
      valid++;
    } else if (!perf_read_errno) {
      perf_read_errno = errno;
    }
    close(fd);
  }

  if (valid == 0) {
    uint64_t t0 = rdtscp64();
    for (size_t i = 0; i < blocks; i++) {
      AES_encrypt(in, out, &aes_key);
      in[(i + out[0]) & 0xF] ^= out[(i + 7) & 0xF];
      g_sink ^= out[i & 0xF];
    }
    {
      uint64_t t1 = rdtscp64();
      double metric_per_1k = ((double)(t1 - t0) * 1000.0) / (double)blocks;
      printf("metric_kind=cycles\n");
      printf("metric_per_1k=%.6f\n", metric_per_1k);
      printf("avg_misses=-1\n");
      printf("perf_open_errno=%d\n", perf_open_errno);
      printf("perf_reset_errno=%d\n", perf_reset_errno);
      printf("perf_enable_errno=%d\n", perf_enable_errno);
      printf("perf_read_errno=%d\n", perf_read_errno);
      printf("sink=%u\n", (unsigned)g_sink);
    }
    return 0;
  }

  {
    double avg_misses = misses_total / (double)valid;
    double metric_per_1k = avg_misses * 1000.0 / (double)blocks;
    printf("metric_kind=cache_misses\n");
    printf("metric_per_1k=%.6f\n", metric_per_1k);
    printf("avg_misses=%.2f\n", avg_misses);
    printf("sink=%u\n", (unsigned)g_sink);
  }
  return 0;
}
