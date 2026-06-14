#define _GNU_SOURCE

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>

#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t rdtscp64(void) {
  unsigned aux = 0;
  return __rdtscp(&aux);
}
#else
static inline uint64_t rdtscp64(void) { return 0; }
#endif

static volatile uint64_t g_sink = 0;

static uint64_t xorshift64(uint64_t *s) {
  uint64_t x = *s;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *s = x;
  return x;
}

static void fill_random(uint8_t *buf, size_t n, uint64_t *seed) {
  size_t i = 0;
  while (i < n) {
    uint64_t x = xorshift64(seed);
    for (int j = 0; j < 8 && i < n; j++, i++)
      buf[i] = (uint8_t)(x >> (j * 8));
  }
}

static double calc_stddev(const uint64_t *arr, size_t n) {
  double mean = 0.0, var = 0.0;
  if (!n)
    return 0.0;
  for (size_t i = 0; i < n; i++)
    mean += (double)arr[i];
  mean /= (double)n;
  for (size_t i = 0; i < n; i++) {
    double d = (double)arr[i] - mean;
    var += d * d;
  }
  return sqrt(var / (double)n);
}

static double calc_mean(const uint64_t *arr, size_t n) {
  double mean = 0.0;
  if (!n)
    return 0.0;
  for (size_t i = 0; i < n; i++)
    mean += (double)arr[i];
  return mean / (double)n;
}

int main(void) {
  enum { KEYS = 80, ITERS = 20, BYTES = 256 };
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *mod = BN_new();
  BIGNUM *base = BN_new();
  BIGNUM *exp = BN_new();
  BIGNUM *out = BN_new();
  BN_MONT_CTX *mont = BN_MONT_CTX_new();
  uint64_t timings_var[KEYS];
  uint64_t timings_ct[KEYS];
  uint8_t exponents[KEYS][BYTES];
  uint64_t seed = 0x52a8f3c94b17d6e1ULL;
  uint8_t tmp[BYTES];

  if (!ctx || !mod || !base || !exp || !out || !mont)
    return 1;

  fill_random(tmp, BYTES, &seed);
  tmp[0] |= 0x80;
  tmp[BYTES - 1] |= 1;
  if (!BN_bin2bn(tmp, BYTES, mod))
    return 2;

  fill_random(tmp, BYTES, &seed);
  tmp[0] |= 0x40;
  if (!BN_bin2bn(tmp, BYTES, base))
    return 3;
  if (!BN_mod(base, base, mod, ctx))
    return 4;

  if (!BN_MONT_CTX_set(mont, mod, ctx))
    return 5;

  for (int k = 0; k < KEYS; k++) {
    fill_random(exponents[k], BYTES, &seed);
    exponents[k][0] |= 0x80;
    exponents[k][BYTES - 1] |= 1;
  }

  for (int k = 0; k < KEYS; k++) {
    uint64_t t0_var, t0_ct;
    if (!BN_bin2bn(exponents[k], BYTES, exp))
      return 6;

    /* warm up both paths on identical key/material */
    if (!BN_mod_exp_mont(out, base, exp, mod, ctx, mont))
      return 7;
    g_sink ^= BN_get_word(out);
    if (!BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, mont))
      return 8;
    g_sink ^= BN_get_word(out);

    if ((k & 1) == 0) {
      t0_var = rdtscp64();
      for (int i = 0; i < ITERS; i++) {
        if (!BN_mod_exp_mont(out, base, exp, mod, ctx, mont))
          return 9;
        g_sink ^= BN_get_word(out);
      }
      timings_var[k] = rdtscp64() - t0_var;

      t0_ct = rdtscp64();
      for (int i = 0; i < ITERS; i++) {
        if (!BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, mont))
          return 10;
        g_sink ^= BN_get_word(out);
      }
      timings_ct[k] = rdtscp64() - t0_ct;
    } else {
      t0_ct = rdtscp64();
      for (int i = 0; i < ITERS; i++) {
        if (!BN_mod_exp_mont_consttime(out, base, exp, mod, ctx, mont))
          return 11;
        g_sink ^= BN_get_word(out);
      }
      timings_ct[k] = rdtscp64() - t0_ct;

      t0_var = rdtscp64();
      for (int i = 0; i < ITERS; i++) {
        if (!BN_mod_exp_mont(out, base, exp, mod, ctx, mont))
          return 12;
        g_sink ^= BN_get_word(out);
      }
      timings_var[k] = rdtscp64() - t0_var;
    }
  }

  {
    double var_std = calc_stddev(timings_var, KEYS);
    double ct_std = calc_stddev(timings_ct, KEYS);
    double var_mean = calc_mean(timings_var, KEYS);
    double ct_mean = calc_mean(timings_ct, KEYS);
    double ratio = ct_std > 0.0 ? var_std / ct_std : -1.0;
    double var_cv = var_mean > 0.0 ? var_std / var_mean : -1.0;
    double ct_cv = ct_mean > 0.0 ? ct_std / ct_mean : -1.0;
    double cv_ratio = ct_cv > 0.0 ? var_cv / ct_cv : -1.0;
    printf("var_mean_cycles=%.2f\n", var_mean);
    printf("const_mean_cycles=%.2f\n", ct_mean);
    printf("var_std_cycles=%.2f\n", var_std);
    printf("const_std_cycles=%.2f\n", ct_std);
    printf("var_cv=%.6f\n", var_cv);
    printf("const_cv=%.6f\n", ct_cv);
    printf("ratio=%.4f\n", ratio);
    printf("cv_ratio=%.4f\n", cv_ratio);
    printf("sink=%llu\n", (unsigned long long)g_sink);
  }

  BN_MONT_CTX_free(mont);
  BN_free(out);
  BN_free(exp);
  BN_free(base);
  BN_free(mod);
  BN_CTX_free(ctx);
  return 0;
}
