#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static volatile uint8_t g_sink = 0;

int main(int argc, char **argv) {
  size_t blocks = 10000000;
  uint8_t key[16];
  uint8_t in[16];
  uint8_t out[16];
  AES_KEY aes_key;
  struct timespec ts0 = {0}, ts1 = {0};
  uint64_t t0 = 0, t1 = 0;

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

  clock_gettime(CLOCK_MONOTONIC_RAW, &ts0);
  t0 = rdtscp64();
  for (size_t i = 0; i < blocks; i++) {
    AES_encrypt(in, out, &aes_key);
    in[(i + out[0]) & 0xF] ^= out[(i + 7) & 0xF];
    g_sink ^= out[i & 0xF];
  }
  t1 = rdtscp64();
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

  {
    uint64_t dt_tsc = t1 > t0 ? (t1 - t0) : 0;
    uint64_t dt_ns = 0;
    if (ts1.tv_sec > ts0.tv_sec || (ts1.tv_sec == ts0.tv_sec && ts1.tv_nsec >= ts0.tv_nsec)) {
      dt_ns = (uint64_t)(ts1.tv_sec - ts0.tv_sec) * 1000000000ULL +
              (uint64_t)(ts1.tv_nsec - ts0.tv_nsec);
    }
    printf("metric_kind=cycles\n");
    printf("blocks=%zu\n", blocks);
    printf("total_cycles=%llu\n", (unsigned long long)dt_tsc);
    printf("total_ns=%llu\n", (unsigned long long)dt_ns);
    printf("cycles_per_call=%.6f\n", blocks ? (double)dt_tsc / (double)blocks : 0.0);
    printf("ns_per_call=%.6f\n", blocks ? (double)dt_ns / (double)blocks : 0.0);
    printf("throughput_ops_per_s=%.6f\n", dt_ns ? (double)blocks * 1.0e9 / (double)dt_ns : 0.0);
    printf("sink=%u\n", (unsigned)g_sink);
  }
  return 0;
}
