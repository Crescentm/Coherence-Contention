#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

static volatile uint64_t g_sink = 0;

#if defined(__AES__) && defined(__x86_64__)
__attribute__((noinline))
static uint64_t run_aesenc_probe(size_t rounds) {
  __m128i x0 = _mm_set_epi64x(0x1122334455667788ULL, 0x99aabbccddeeff00ULL);
  __m128i x1 = _mm_set_epi64x(0x1021324354657687ULL, 0x98badcfe01234567ULL);
  __m128i rk0 = _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL);
  __m128i rk1 = _mm_set_epi64x(0xf0e0d0c0b0a09080ULL, 0x7060504030201000ULL);
  for (size_t i = 0; i < rounds; i++) {
    x0 = _mm_aesenc_si128(x0, rk0);
    x1 = _mm_aesenc_si128(x1, rk1);
    x0 = _mm_aesenc_si128(x0, x1);
    x1 = _mm_aesenc_si128(x1, x0);
    x0 = _mm_aesenc_si128(x0, rk1);
    x1 = _mm_aesenc_si128(x1, rk0);
    x0 = _mm_aesenc_si128(x0, _mm_set1_epi64x((long long)i));
    x1 = _mm_aesenc_si128(x1, _mm_set1_epi64x((long long)(i * 0x9e3779b97f4a7c15ULL)));
  }
  x0 = _mm_xor_si128(x0, x1);
  g_sink ^= (uint64_t)_mm_cvtsi128_si64(x0);
  return (uint64_t)_mm_cvtsi128_si64(x0);
}
#else
__attribute__((noinline))
static uint64_t run_aesenc_probe(size_t rounds) {
  uint64_t s = 0x123456789abcdef0ULL;
  for (size_t i = 0; i < rounds; i++) {
    s ^= (uint64_t)i * 0x9e3779b97f4a7c15ULL;
    s = (s << 13) | (s >> 51);
  }
  g_sink ^= s;
  return s;
}
#endif

int main(int argc, char **argv) {
  size_t rounds = 100000000;
  if (argc >= 2) {
    char *end = NULL;
    unsigned long long v = strtoull(argv[1], &end, 10);
    if (end && *end == '\0' && v > 0)
      rounds = (size_t)v;
  }
  uint64_t v = run_aesenc_probe(rounds);
  printf("sink=%llu\n", (unsigned long long)(v ^ g_sink));
  return 0;
}
