#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/aes.h>
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

enum {
  CRYPTO_REQ_AES = 0x01,
  CRYPTO_REQ_RSA = 0x02,
  CRYPTO_REQ_INFO = 0x03,
};

struct server_cfg {
  int port;
  int rsa_consttime;
  int reps;
};

struct server_ctx {
  AES_KEY aes_key;
  BIGNUM *rsa_mod;
  BIGNUM *rsa_exp;
  BN_MONT_CTX *rsa_mont;
  BN_CTX *bn_ctx;
  volatile uint64_t sink;
};

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

static ssize_t readn(int fd, void *buf, size_t n) {
  uint8_t *p = (uint8_t *)buf;
  size_t done = 0;
  while (done < n) {
    ssize_t r = read(fd, p + done, n - done);
    if (r == 0)
      return (ssize_t)done;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    done += (size_t)r;
  }
  return (ssize_t)done;
}

static ssize_t writen(int fd, const void *buf, size_t n) {
  const uint8_t *p = (const uint8_t *)buf;
  size_t done = 0;
  while (done < n) {
    ssize_t w = write(fd, p + done, n - done);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    done += (size_t)w;
  }
  return (ssize_t)done;
}

static int parse_arg_int(const char *s, int *out) {
  char *end = NULL;
  long v = strtol(s, &end, 10);
  if (!s[0] || (end && *end))
    return -1;
  if (v < 0 || v > 1 << 30)
    return -1;
  *out = (int)v;
  return 0;
}

static void parse_args(int argc, char **argv, struct server_cfg *cfg) {
  cfg->port = 5555;
  cfg->rsa_consttime = 0;
  cfg->reps = 1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      (void)parse_arg_int(argv[++i], &cfg->port);
    } else if (strcmp(argv[i], "--rsa-consttime") == 0) {
      cfg->rsa_consttime = 1;
    } else if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc) {
      (void)parse_arg_int(argv[++i], &cfg->reps);
    }
  }
  if (cfg->port <= 0 || cfg->port > 65535)
    cfg->port = 5555;
  if (cfg->reps <= 0)
    cfg->reps = 1;
}

static int setup_listener(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  struct sockaddr_in addr;
  if (fd < 0)
    return -1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  if (listen(fd, 32) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int init_ctx(struct server_ctx *ctx) {
  uint8_t key[16];
  uint8_t tmp[256];
  uint64_t seed = rdtscp64() ^ (uint64_t)time(NULL) ^ 0x9e3779b97f4a7c15ULL;

  memset(ctx, 0, sizeof(*ctx));
  fill_random(key, sizeof(key), &seed);
  if (AES_set_encrypt_key(key, 128, &ctx->aes_key) != 0)
    return -1;

  ctx->rsa_mod = BN_new();
  ctx->rsa_exp = BN_new();
  ctx->rsa_mont = BN_MONT_CTX_new();
  ctx->bn_ctx = BN_CTX_new();
  if (!ctx->rsa_mod || !ctx->rsa_exp || !ctx->rsa_mont || !ctx->bn_ctx)
    return -1;

  fill_random(tmp, sizeof(tmp), &seed);
  tmp[0] |= 0x80;
  tmp[sizeof(tmp) - 1] |= 1;
  if (!BN_bin2bn(tmp, (int)sizeof(tmp), ctx->rsa_mod))
    return -1;

  fill_random(tmp, sizeof(tmp), &seed);
  tmp[0] |= 0x80;
  tmp[sizeof(tmp) - 1] |= 1;
  if (!BN_bin2bn(tmp, (int)sizeof(tmp), ctx->rsa_exp))
    return -1;

  if (!BN_MONT_CTX_set(ctx->rsa_mont, ctx->rsa_mod, ctx->bn_ctx))
    return -1;
  return 0;
}

static void free_ctx(struct server_ctx *ctx) {
  BN_MONT_CTX_free(ctx->rsa_mont);
  BN_free(ctx->rsa_mod);
  BN_free(ctx->rsa_exp);
  BN_CTX_free(ctx->bn_ctx);
}

static int handle_req_info(int cfd, const struct server_cfg *cfg) {
  char msg[128];
  int n = snprintf(msg, sizeof(msg),
                   "crypto_server port=%d rsa_consttime=%d reps=%d\n", cfg->port,
                   cfg->rsa_consttime, cfg->reps);
  if (n < 0)
    return -1;
  return writen(cfd, msg, (size_t)n) == n ? 0 : -1;
}

static int handle_req_aes(int cfd, struct server_ctx *ctx, int reps) {
  uint8_t in[16];
  uint8_t out[16];
  if (readn(cfd, in, sizeof(in)) != (ssize_t)sizeof(in))
    return -1;
  for (int i = 0; i < reps; i++) {
    AES_encrypt(in, out, &ctx->aes_key);
    in[(i + out[0]) & 0xF] ^= out[(i + 3) & 0xF];
    ctx->sink ^= out[i & 0xF];
  }
  return writen(cfd, out, sizeof(out)) == (ssize_t)sizeof(out) ? 0 : -1;
}

static int handle_req_rsa(int cfd, struct server_ctx *ctx, int reps,
                          int use_consttime) {
  uint8_t in[256];
  uint8_t out[256];
  BIGNUM *base = NULL;
  BIGNUM *res = NULL;
  int out_len = 0;
  int ret = -1;

  if (readn(cfd, in, sizeof(in)) != (ssize_t)sizeof(in))
    return -1;
  base = BN_bin2bn(in, (int)sizeof(in), NULL);
  res = BN_new();
  if (!base || !res)
    goto out;
  if (!BN_mod(base, base, ctx->rsa_mod, ctx->bn_ctx))
    goto out;

  for (int i = 0; i < reps; i++) {
    int ok = use_consttime
                 ? BN_mod_exp_mont_consttime(res, base, ctx->rsa_exp,
                                             ctx->rsa_mod, ctx->bn_ctx,
                                             ctx->rsa_mont)
                 : BN_mod_exp_mont(res, base, ctx->rsa_exp, ctx->rsa_mod,
                                   ctx->bn_ctx, ctx->rsa_mont);
    if (!ok)
      goto out;
    ctx->sink ^= (uint64_t)BN_get_word(res) ^ (uint64_t)i;
  }

  memset(out, 0, sizeof(out));
  out_len = BN_num_bytes(res);
  if (out_len < 0 || out_len > (int)sizeof(out))
    goto out;
  if (BN_bn2bin(res, out + (sizeof(out) - (size_t)out_len)) != out_len)
    goto out;
  if (writen(cfd, out, sizeof(out)) != (ssize_t)sizeof(out))
    goto out;
  ret = 0;

out:
  BN_free(base);
  BN_free(res);
  return ret;
}

static int handle_client(int cfd, struct server_ctx *ctx,
                         const struct server_cfg *cfg) {
  uint8_t op = 0;
  ssize_t r = readn(cfd, &op, 1);
  if (r != 1)
    return -1;
  if (op == CRYPTO_REQ_INFO)
    return handle_req_info(cfd, cfg);
  if (op == CRYPTO_REQ_AES)
    return handle_req_aes(cfd, ctx, cfg->reps);
  if (op == CRYPTO_REQ_RSA)
    return handle_req_rsa(cfd, ctx, cfg->reps, cfg->rsa_consttime);
  return -1;
}

int main(int argc, char **argv) {
  struct server_cfg cfg;
  struct server_ctx ctx;
  int lfd = -1;

  parse_args(argc, argv, &cfg);
  if (init_ctx(&ctx) != 0) {
    fprintf(stderr, "init_ctx failed\n");
    return 1;
  }

  lfd = setup_listener(cfg.port);
  if (lfd < 0) {
    fprintf(stderr, "listen failed on port %d: %s\n", cfg.port, strerror(errno));
    free_ctx(&ctx);
    return 1;
  }

  fprintf(stderr, "crypto_server listening on 0.0.0.0:%d mode=%s reps=%d\n",
          cfg.port, cfg.rsa_consttime ? "rsa_consttime" : "rsa_var", cfg.reps);
  fflush(stderr);

  for (;;) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      usleep(1000);
      continue;
    }
    (void)handle_client(cfd, &ctx, &cfg);
    close(cfd);
  }

  close(lfd);
  free_ctx(&ctx);
  return 0;
}

