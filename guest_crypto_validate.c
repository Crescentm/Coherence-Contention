#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <x86intrin.h>
#include <wmmintrin.h>
#endif

#ifdef __has_include
#if __has_include(<linux/perf_event.h>)
#include <linux/perf_event.h>
#endif
#endif

#define DEBUGCON_PORT 0xE9
#define READ_CHUNK 4096

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

static void debugcon_puts(const char *s) {
  while (*s) {
#if defined(__x86_64__)
    __asm__ __volatile__("outb %b0, %w1" : : "a"((uint8_t)*s), "Nd"(DEBUGCON_PORT));
#endif
    s++;
  }
}

static void debugcon_printf(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  int n;
  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n > 0)
    debugcon_puts(buf);
}

static int init_debugcon(void) {
  if (ioperm(DEBUGCON_PORT, 1, 1) != 0)
    return -1;
  return 0;
}

static int path_exists(const char *path) {
  return access(path, F_OK) == 0 ? 1 : 0;
}

static long count_token_in_file(const char *path, const char *token) {
  int fd = open(path, O_RDONLY);
  char *buf = NULL;
  ssize_t n;
  size_t token_len = strlen(token);
  long count = 0;
  size_t keep = token_len > 1 ? token_len - 1 : 0;
  size_t prev_len = 0;
  char prev[128];

  if (fd < 0)
    return -1;
  if (keep >= sizeof(prev))
    keep = sizeof(prev) - 1;

  buf = malloc(READ_CHUNK + sizeof(prev));
  if (!buf) {
    close(fd);
    return -1;
  }

  while ((n = read(fd, buf + prev_len, READ_CHUNK)) > 0) {
    size_t total = prev_len + (size_t)n;
    size_t i = 0;

    if (prev_len) {
      memcpy(buf, prev, prev_len);
    }
    while (i + token_len <= total) {
      if (memcmp(buf + i, token, token_len) == 0)
        count++;
      i++;
    }

    if (keep > total)
      prev_len = total;
    else
      prev_len = keep;
    if (prev_len)
      memcpy(prev, buf + total - prev_len, prev_len);
  }

  free(buf);
  close(fd);
  if (n < 0)
    return -1;
  return count;
}

static int parse_openssl_version(const char *path, char *out, size_t out_sz) {
  FILE *fp = fopen(path, "r");
  char line[256];
  char major[32] = {0}, minor[32] = {0}, patch[32] = {0};
  if (!fp)
    return -1;
  while (fgets(line, sizeof(line), fp)) {
    if (sscanf(line, "MAJOR=%31s", major) == 1)
      continue;
    if (sscanf(line, "MINOR=%31s", minor) == 1)
      continue;
    if (sscanf(line, "PATCH=%31s", patch) == 1)
      continue;
  }
  fclose(fp);
  if (!major[0] || !minor[0] || !patch[0])
    return -1;
  snprintf(out, out_sz, "%s.%s.%s", major, minor, patch);
  return 0;
}

static int parse_libgcrypt_version(const char *path, char *out, size_t out_sz) {
  FILE *fp = fopen(path, "r");
  char line[512];
  char major[32] = {0}, minor[32] = {0}, micro[32] = {0};
  if (!fp)
    return -1;
  while (fgets(line, sizeof(line), fp)) {
    sscanf(line, "m4_define(mym4_version_major, [%31[^]]", major);
    sscanf(line, "m4_define(mym4_version_minor, [%31[^]]", minor);
    sscanf(line, "m4_define(mym4_version_micro, [%31[^]]", micro);
  }
  fclose(fp);
  if (major[0] && minor[0] && micro[0]) {
    snprintf(out, out_sz, "%s.%s.%s", major, minor, micro);
    return 0;
  }
  return -1;
}

static int run_aes_real_bench(const char *cmd, double *metric_per_1k,
                              double *avg_misses, int *pmu_ok,
                              int *perf_open_errno_out,
                              int *perf_reset_errno_out,
                              int *perf_enable_errno_out,
                              int *perf_read_errno_out) {
  FILE *fp = popen(cmd, "r");
  char line[256];
  char kind[64] = {0};
  int got_metric = 0;
  int got_avg = 0;
  int got_kind = 0;
  int perf_open_errno = 0;
  int perf_reset_errno = 0;
  int perf_enable_errno = 0;
  int perf_read_errno = 0;
  if (!fp)
    return -1;
  if (pmu_ok)
    *pmu_ok = 0;
  if (perf_open_errno_out)
    *perf_open_errno_out = 0;
  if (perf_reset_errno_out)
    *perf_reset_errno_out = 0;
  if (perf_enable_errno_out)
    *perf_enable_errno_out = 0;
  if (perf_read_errno_out)
    *perf_read_errno_out = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (sscanf(line, "metric_kind=%63s", kind) == 1) {
      got_kind = 1;
      continue;
    }
    if (sscanf(line, "metric_per_1k=%lf", metric_per_1k) == 1) {
      got_metric = 1;
      continue;
    }
    if (sscanf(line, "avg_misses=%lf", avg_misses) == 1) {
      got_avg = 1;
      continue;
    }
    if (sscanf(line, "perf_open_errno=%d", &perf_open_errno) == 1)
      continue;
    if (sscanf(line, "perf_reset_errno=%d", &perf_reset_errno) == 1)
      continue;
    if (sscanf(line, "perf_enable_errno=%d", &perf_enable_errno) == 1)
      continue;
    if (sscanf(line, "perf_read_errno=%d", &perf_read_errno) == 1)
      continue;
  }
  if (pclose(fp) != 0)
    return -1;
  if (got_kind && pmu_ok)
    *pmu_ok = (strcmp(kind, "cache_misses") == 0) ? 1 : 0;
  if (perf_open_errno_out)
    *perf_open_errno_out = perf_open_errno;
  if (perf_reset_errno_out)
    *perf_reset_errno_out = perf_reset_errno;
  if (perf_enable_errno_out)
    *perf_enable_errno_out = perf_enable_errno;
  if (perf_read_errno_out)
    *perf_read_errno_out = perf_read_errno;
  return (got_metric && got_avg) ? 0 : -1;
}

static int run_rsa_real_bench(const char *cmd, double *var_mean,
                              double *ct_mean, double *var_std,
                              double *ct_std, double *var_cv, double *ct_cv,
                              double *ratio, double *cv_ratio) {
  FILE *fp = popen(cmd, "r");
  char line[256];
  int got_var_mean = 0;
  int got_ct_mean = 0;
  int got_var = 0;
  int got_ct = 0;
  int got_var_cv = 0;
  int got_ct_cv = 0;
  int got_ratio = 0;
  int got_cv_ratio = 0;
  if (!fp)
    return -1;
  while (fgets(line, sizeof(line), fp)) {
    if (sscanf(line, "var_mean_cycles=%lf", var_mean) == 1) {
      got_var_mean = 1;
      continue;
    }
    if (sscanf(line, "const_mean_cycles=%lf", ct_mean) == 1) {
      got_ct_mean = 1;
      continue;
    }
    if (sscanf(line, "var_std_cycles=%lf", var_std) == 1) {
      got_var = 1;
      continue;
    }
    if (sscanf(line, "const_std_cycles=%lf", ct_std) == 1) {
      got_ct = 1;
      continue;
    }
    if (sscanf(line, "var_cv=%lf", var_cv) == 1) {
      got_var_cv = 1;
      continue;
    }
    if (sscanf(line, "const_cv=%lf", ct_cv) == 1) {
      got_ct_cv = 1;
      continue;
    }
    if (sscanf(line, "ratio=%lf", ratio) == 1) {
      got_ratio = 1;
      continue;
    }
    if (sscanf(line, "cv_ratio=%lf", cv_ratio) == 1) {
      got_cv_ratio = 1;
      continue;
    }
  }
  if (pclose(fp) != 0)
    return -1;
  return (got_var_mean && got_ct_mean && got_var && got_ct && got_var_cv &&
          got_ct_cv && got_ratio && got_cv_ratio)
             ? 0
             : -1;
}

#if defined(__x86_64__)
static inline uint64_t rdtscp64(void) {
  unsigned aux = 0;
  return __rdtscp(&aux);
}
#else
static inline uint64_t rdtscp64(void) { return 0; }
#endif

static volatile uint64_t g_bench_sink = 0;

static uint64_t run_ttable_like(size_t ops) {
  enum { TABLE_N = 4096 };
  static uint32_t t0[TABLE_N], t1[TABLE_N], t2[TABLE_N], t3[TABLE_N];
  static int inited = 0;
  uint32_t s = 0x12345678u;
  size_t i;
  if (!inited) {
    for (i = 0; i < TABLE_N; i++) {
      t0[i] = (uint32_t)(i * 0x01010101u);
      t1[i] = (uint32_t)(i * 0x02020203u);
      t2[i] = (uint32_t)(i * 0x04040407u);
      t3[i] = (uint32_t)(i * 0x0808080bu);
    }
    inited = 1;
  }
  for (i = 0; i < ops; i++) {
    uint32_t x = s ^ (uint32_t)(i * 0x9e3779b9u);
    uint32_t b0 = x & (TABLE_N - 1);
    uint32_t b1 = (x >> 3) & (TABLE_N - 1);
    uint32_t b2 = (x >> 7) & (TABLE_N - 1);
    uint32_t b3 = (x >> 11) & (TABLE_N - 1);
    s = t0[b0] ^ t1[b1] ^ t2[b2] ^ t3[b3] ^ x;
    s = (s << 5) | (s >> 27);
  }
  g_bench_sink ^= s;
  return s;
}

#if defined(__AES__) && defined(__x86_64__)
static uint64_t run_aesni_like(size_t ops) {
  __m128i x = _mm_set_epi64x(0x1122334455667788ULL, 0x99aabbccddeeff00ULL);
  __m128i rk = _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL);
  size_t i;
  for (i = 0; i < ops; i++) {
    x = _mm_aesenc_si128(x, rk);
    x = _mm_aesenc_si128(x, _mm_set1_epi64x((long long)i));
  }
  g_bench_sink ^= (uint64_t)_mm_cvtsi128_si64(x);
  return (uint64_t)_mm_cvtsi128_si64(x);
}
#else
static uint64_t run_aesni_like(size_t ops) {
  return run_ttable_like(ops);
}
#endif

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

static int open_cache_miss_counter(void) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CACHE_MISSES;
  attr.disabled = 1;
  attr.exclude_kernel = 0;
  attr.exclude_hv = 0;
  {
    int fd = perf_event_open_local(&attr, 0, -1, -1, 0);
    if (fd < 0 && errno == E2BIG) {
      uint32_t ksz = attr.size;
      if (ksz >= PERF_ATTR_SIZE_VER0 && ksz < sizeof(attr)) {
        attr.size = ksz;
        fd = perf_event_open_local(&attr, 0, -1, -1, 0);
      }
    }
    return fd;
  }
}

static __attribute__((unused)) double measure_cycles_per_1k(size_t ops,
                                                            int use_aesni) {
  uint64_t t0, t1;
  if (ops == 0)
    return -1;
  t0 = rdtscp64();
  if (use_aesni)
    run_aesni_like(ops);
  else
    run_ttable_like(ops);
  t1 = rdtscp64();
  return ((double)(t1 - t0) * 1000.0) / (double)ops;
}

static __attribute__((unused)) double
measure_cache_misses_per_1k(size_t ops, int use_aesni, int repeats, int *ok_out,
                            double *avg_misses_out) {
  int r;
  uint64_t total = 0;
  int valid = 0;
  if (ok_out)
    *ok_out = 0;
  if (avg_misses_out)
    *avg_misses_out = -1.0;
  if (ops == 0 || repeats <= 0)
    return -1;

  for (r = 0; r < repeats; r++) {
    int fd = open_cache_miss_counter();
    uint64_t misses = 0;
    ssize_t nread;
    if (fd < 0)
      continue;

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) != 0) {
      close(fd);
      continue;
    }
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
      close(fd);
      continue;
    }

    if (use_aesni)
      run_aesni_like(ops);
    else
      run_ttable_like(ops);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    nread = read(fd, &misses, sizeof(misses));
    close(fd);
    if (nread != (ssize_t)sizeof(misses))
      continue;

    total += misses;
    valid++;
  }

  if (valid == 0)
    return -1;
  if (ok_out)
    *ok_out = 1;
  if (avg_misses_out)
    *avg_misses_out = (double)total / (double)valid;
  return ((double)total / (double)valid) * 1000.0 / (double)ops;
}

static uint64_t ct_select_u64(uint64_t a, uint64_t b, uint64_t bit) {
  uint64_t mask = 0ULL - (bit & 1ULL);
  return (a & ~mask) | (b & mask);
}

static uint64_t xorshift64(uint64_t *s) {
  uint64_t x = *s;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *s = x;
  return x;
}

static double calc_stddev(const uint64_t *arr, size_t n) {
  double mean = 0.0, var = 0.0;
  size_t i;
  if (n == 0)
    return 0.0;
  for (i = 0; i < n; i++)
    mean += (double)arr[i];
  mean /= (double)n;
  for (i = 0; i < n; i++) {
    double d = (double)arr[i] - mean;
    var += d * d;
  }
  var /= (double)n;
  return sqrt(var);
}

static inline uint64_t rotl64(uint64_t x, unsigned r) {
  return (x << r) | (x >> (64U - r));
}

static uint64_t rsa_mul_heavy(uint64_t a, uint64_t b) {
  enum { TAB_N = 1 << 16, ROUNDS = 192 };
  static uint64_t tab[TAB_N];
  static int inited = 0;
  uint64_t x;
  int i;
  if (!inited) {
    uint64_t s = 0x7f4a7c159e3779b9ULL;
    for (i = 0; i < TAB_N; i++) {
      s ^= s << 13;
      s ^= s >> 7;
      s ^= s << 17;
      tab[i] = s ^ (uint64_t)i * 0xD6E8FEB86659FD93ULL;
    }
    inited = 1;
  }

  x = a ^ rotl64(b, 23) ^ 0x9E3779B97F4A7C15ULL;
  for (i = 0; i < ROUNDS; i++) {
    uint32_t idx = (uint32_t)(x ^ (x >> 17) ^ (uint64_t)(i * 0x9e37U)) & (TAB_N - 1);
    x = rotl64(x + tab[idx] + 0xD1B54A32D192ED03ULL, 11);
    x ^= (x >> 29);
  }
  g_bench_sink ^= x;
  return x;
}

static uint64_t rsa_mul_const(uint64_t a, uint64_t b) {
  enum { ROUNDS = 192 };
  uint64_t x = a ^ rotl64(b, 29) ^ 0xA24BAED4963EE407ULL;
  int i;
  for (i = 0; i < ROUNDS; i++) {
    x = x * 0x9E3779B97F4A7C15ULL + 0xBF58476D1CE4E5B9ULL + (uint64_t)i;
    x ^= rotl64(x, 13);
    x = x * 0x94D049BB133111EBULL;
  }
  g_bench_sink ^= x;
  return x;
}

enum {
  RSA_SIM_BITS = 2048,
  RSA_SIM_LIMBS = RSA_SIM_BITS / 64,
};

static void gen_exp_2048(uint64_t out[RSA_SIM_LIMBS], uint64_t *seed) {
  int i;
  for (i = 0; i < RSA_SIM_LIMBS; i++)
    out[i] = xorshift64(seed);
  out[RSA_SIM_LIMBS - 1] |= (1ULL << 63);
  out[0] |= 1ULL;
}

static inline uint64_t exp_bit_2048(const uint64_t exp[RSA_SIM_LIMBS], int bit_idx) {
  return (exp[bit_idx >> 6] >> (bit_idx & 63)) & 1ULL;
}

static uint64_t rsa_modexp_var_sim(const uint64_t exp[RSA_SIM_LIMBS], uint64_t base) {
  uint64_t r = 1;
  int i;
  for (i = RSA_SIM_BITS - 1; i >= 0; i--) {
    r = rsa_mul_const(r, r);
    if (exp_bit_2048(exp, i)) {
      r = rsa_mul_heavy(r, base ^ (uint64_t)i);
      r = rsa_mul_heavy(r, base ^ (uint64_t)(i * 3 + 1));
    }
  }
  return r;
}

static uint64_t rsa_modexp_ct_sim(const uint64_t exp[RSA_SIM_LIMBS], uint64_t base) {
  uint64_t r = 1;
  int i;
  for (i = RSA_SIM_BITS - 1; i >= 0; i--) {
    uint64_t sq = rsa_mul_const(r, r);
    uint64_t mul = rsa_mul_const(sq, base ^ (uint64_t)i);
    r = ct_select_u64(sq, mul, exp_bit_2048(exp, i));
  }
  return r;
}

static __attribute__((unused)) void measure_rsa_proxy(double *std_var,
                                                      double *std_ct) {
  enum { KEYS = 120, ITERS = 64 };
  uint64_t exponents[KEYS][RSA_SIM_LIMBS];
  uint64_t timings_var[KEYS];
  uint64_t timings_ct[KEYS];
  uint64_t seed = 0x31415926abcdefULL;
  const uint64_t base = 0x1234567890abcdefULL;
  int k, i;

  for (k = 0; k < KEYS; k++)
    gen_exp_2048(exponents[k], &seed);

  for (k = 0; k < KEYS; k++) {
    uint64_t t0 = rdtscp64();
    uint64_t acc = 0;
    for (i = 0; i < ITERS; i++)
      acc ^= rsa_modexp_var_sim(exponents[k], base + (uint64_t)i);
    timings_var[k] = rdtscp64() - t0;
    seed ^= acc;
  }

  for (k = 0; k < KEYS; k++) {
    uint64_t t0 = rdtscp64();
    uint64_t acc = 0;
    for (i = 0; i < ITERS; i++)
      acc ^= rsa_modexp_ct_sim(exponents[k], base + (uint64_t)i);
    timings_ct[k] = rdtscp64() - t0;
    seed ^= acc;
  }

  *std_var = calc_stddev(timings_var, KEYS);
  *std_ct = calc_stddev(timings_ct, KEYS);
}

int main(void) {
  const char *openssl_dir = "/opt/crypto-src/openssl-3.4.0";
  const char *g176_dir = "/opt/crypto-src/libgcrypt-1.7.6";
  const char *g178_dir = "/opt/crypto-src/libgcrypt-1.7.8";

  char openssl_ver[64] = "unknown";
  char g176_ver[64] = "unknown";
  char g178_ver[64] = "unknown";
  double aes_noasm_metric_1k = -1.0;
  double aes_aesni_metric_1k = -1.0;
  double aes_noasm_misses_avg = -1.0;
  double aes_aesni_misses_avg = -1.0;
  int aes_noasm_pmu_ok = 0;
  int aes_aesni_pmu_ok = 0;
  int aes_noasm_perf_open_errno = 0;
  int aes_noasm_perf_reset_errno = 0;
  int aes_noasm_perf_enable_errno = 0;
  int aes_noasm_perf_read_errno = 0;
  int aes_aesni_perf_open_errno = 0;
  int aes_aesni_perf_reset_errno = 0;
  int aes_aesni_perf_enable_errno = 0;
  int aes_aesni_perf_read_errno = 0;
  double rsa_mean_var = 0.0;
  double rsa_mean_ct = 0.0;
  double rsa_std_var = 0.0;
  double rsa_std_ct = 0.0;
  double rsa_cv_var = 0.0;
  double rsa_cv_ct = 0.0;
  double rsa_ratio = -1.0;
  double rsa_cv_ratio = -1.0;

  if (init_debugcon() != 0)
    return 1;

  debugcon_printf("CRYPTO51 start=1\n");
  debugcon_printf("CRYPTO51 openssl_dir_exists=%d\n", path_exists(openssl_dir));
  debugcon_printf("CRYPTO51 libgcrypt_176_dir_exists=%d\n", path_exists(g176_dir));
  debugcon_printf("CRYPTO51 libgcrypt_178_dir_exists=%d\n", path_exists(g178_dir));

  if (parse_openssl_version("/opt/crypto-src/openssl-3.4.0/VERSION.dat",
                            openssl_ver, sizeof(openssl_ver)) == 0) {
    debugcon_printf("CRYPTO51 openssl_version=%s\n", openssl_ver);
  } else {
    debugcon_printf("CRYPTO51 openssl_version=unknown\n");
  }

  if (parse_libgcrypt_version("/opt/crypto-src/libgcrypt-1.7.6/configure.ac",
                              g176_ver, sizeof(g176_ver)) == 0) {
    debugcon_printf("CRYPTO51 libgcrypt_176_version=%s\n", g176_ver);
  } else {
    debugcon_printf("CRYPTO51 libgcrypt_176_version=unknown\n");
  }

  if (parse_libgcrypt_version("/opt/crypto-src/libgcrypt-1.7.8/configure.ac",
                              g178_ver, sizeof(g178_ver)) == 0) {
    debugcon_printf("CRYPTO51 libgcrypt_178_version=%s\n", g178_ver);
  } else {
    debugcon_printf("CRYPTO51 libgcrypt_178_version=unknown\n");
  }

  debugcon_printf(
      "CRYPTO51 aes_ttable_defs=%ld\n",
      count_token_in_file("/opt/crypto-src/openssl-3.4.0/crypto/aes/aes_core.c",
                          "static const u32 Te0"));
  debugcon_printf(
      "CRYPTO51 aes_ttable_refs=%ld\n",
      count_token_in_file("/opt/crypto-src/openssl-3.4.0/crypto/aes/aes_core.c",
                          "Te0["));
  debugcon_printf(
      "CRYPTO51 openssl_noasm_doc=%ld\n",
      count_token_in_file("/opt/crypto-src/openssl-3.4.0/INSTALL.md", "no-asm"));
  debugcon_printf("CRYPTO51 aesni_source_exists=%d\n",
                  path_exists("/opt/crypto-src/openssl-3.4.0/crypto/aes/asm/aesni-x86_64.pl"));

  if (run_aes_real_bench("/bin/aes_bench_noasm", &aes_noasm_metric_1k,
                         &aes_noasm_misses_avg, &aes_noasm_pmu_ok,
                         &aes_noasm_perf_open_errno,
                         &aes_noasm_perf_reset_errno,
                         &aes_noasm_perf_enable_errno,
                         &aes_noasm_perf_read_errno) != 0 ||
      run_aes_real_bench("/bin/aes_bench_asm", &aes_aesni_metric_1k,
                         &aes_aesni_misses_avg, &aes_aesni_pmu_ok,
                         &aes_aesni_perf_open_errno,
                         &aes_aesni_perf_reset_errno,
                         &aes_aesni_perf_enable_errno,
                         &aes_aesni_perf_read_errno) != 0) {
    debugcon_printf("CRYPTO51 error=aes_real_bench_failed\n");
    return 2;
  }
  if (aes_noasm_pmu_ok && aes_aesni_pmu_ok)
    debugcon_printf("CRYPTO51 aes_metric_type=cache_misses_per_1k_ops_real_path\n");
  else
    debugcon_printf("CRYPTO51 aes_metric_type=cycles_per_1k_ops_real_path\n");
  debugcon_printf("CRYPTO51 aes_perf_event_ok=%d\n",
                  (aes_noasm_pmu_ok && aes_aesni_pmu_ok) ? 1 : 0);
  debugcon_printf("CRYPTO51 aes_noasm_misses_avg=%.2f\n", aes_noasm_misses_avg);
  debugcon_printf("CRYPTO51 aes_aesni_misses_avg=%.2f\n", aes_aesni_misses_avg);
  debugcon_printf("CRYPTO51 aes_noasm_metric_per_1k=%.6f\n", aes_noasm_metric_1k);
  debugcon_printf("CRYPTO51 aes_aesni_metric_per_1k=%.6f\n", aes_aesni_metric_1k);
  debugcon_printf("CRYPTO51 aes_noasm_perf_open_errno=%d\n",
                  aes_noasm_perf_open_errno);
  debugcon_printf("CRYPTO51 aes_noasm_perf_reset_errno=%d\n",
                  aes_noasm_perf_reset_errno);
  debugcon_printf("CRYPTO51 aes_noasm_perf_enable_errno=%d\n",
                  aes_noasm_perf_enable_errno);
  debugcon_printf("CRYPTO51 aes_noasm_perf_read_errno=%d\n",
                  aes_noasm_perf_read_errno);
  debugcon_printf("CRYPTO51 aes_aesni_perf_open_errno=%d\n",
                  aes_aesni_perf_open_errno);
  debugcon_printf("CRYPTO51 aes_aesni_perf_reset_errno=%d\n",
                  aes_aesni_perf_reset_errno);
  debugcon_printf("CRYPTO51 aes_aesni_perf_enable_errno=%d\n",
                  aes_aesni_perf_enable_errno);
  debugcon_printf("CRYPTO51 aes_aesni_perf_read_errno=%d\n",
                  aes_aesni_perf_read_errno);

  if (run_rsa_real_bench("/bin/rsa_bench", &rsa_mean_var, &rsa_mean_ct,
                         &rsa_std_var, &rsa_std_ct, &rsa_cv_var, &rsa_cv_ct,
                         &rsa_ratio, &rsa_cv_ratio) != 0) {
    debugcon_printf("CRYPTO51 error=rsa_real_bench_failed\n");
    return 3;
  }
  debugcon_printf("CRYPTO51 rsa_metric_source=openssl_bn_real_path\n");
  debugcon_printf("CRYPTO51 rsa_var_mean_cycles=%.2f\n", rsa_mean_var);
  debugcon_printf("CRYPTO51 rsa_const_mean_cycles=%.2f\n", rsa_mean_ct);
  debugcon_printf("CRYPTO51 rsa_var_std_cycles=%.2f\n", rsa_std_var);
  debugcon_printf("CRYPTO51 rsa_const_std_cycles=%.2f\n", rsa_std_ct);
  debugcon_printf("CRYPTO51 rsa_var_cv=%.6f\n", rsa_cv_var);
  debugcon_printf("CRYPTO51 rsa_const_cv=%.6f\n", rsa_cv_ct);
  debugcon_printf("CRYPTO51 rsa_std_ratio=%.4f\n", rsa_ratio);
  debugcon_printf("CRYPTO51 rsa_cv_ratio=%.4f\n", rsa_cv_ratio);

  debugcon_printf("CRYPTO51_DONE\n");
  return 0;
}
