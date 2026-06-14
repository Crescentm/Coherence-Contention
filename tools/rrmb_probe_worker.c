#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define NPTCTL_MAGIC 0x4E505443U /* "NPTC" */
#define NPTCTL_CMD_READ_GPA_BATCH 6U

struct nptctl_req {
  uint32_t magic;
  uint16_t cmd;
  uint16_t reserved;
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
} __attribute__((packed));

struct nptctl_resp {
  uint32_t magic;
  uint16_t cmd;
  uint16_t status;   /* 0=ok, 1=error */
  int32_t sys_errno; /* errno when status=1 */
  int32_t kret;      /* ioctl inner ret (param.ret) */
  uint64_t v0;
  uint64_t v1;
  uint64_t v2;
  uint64_t v3;
} __attribute__((packed));

struct opts {
  const char *sock_path;
  const char *out_csv;
  const char *out_bin;
  uint64_t gpa;
  uint32_t mode;
  uint32_t samples;
  uint32_t rounds;
  uint32_t sleep_us;
  uint64_t flags;
};

static int read_full(int fd, void *buf, size_t n) {
  uint8_t *p = (uint8_t *)buf;
  while (n > 0) {
    ssize_t r = read(fd, p, n);
    if (r == 0)
      return 0;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += (size_t)r;
    n -= (size_t)r;
  }
  return 1;
}

static int write_full(int fd, const void *buf, size_t n) {
  const uint8_t *p = (const uint8_t *)buf;
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += (size_t)w;
    n -= (size_t)w;
  }
  return 0;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s --sock <path> --gpa <hex> [options]\n"
          "Options:\n"
          "  --mode <n>        GPA read mode (default: 2, ciphertext nocache)\n"
          "  --samples <n>     batch samples per round (default: 1024)\n"
          "  --rounds <n>      rounds (default: 1)\n"
          "  --sleep-us <n>    sleep between rounds (default: 0)\n"
          "  --flags <hex>     ioctl flags (default: 0)\n"
          "  --out-csv <path>  write CSV: round,idx,tsc\n"
          "  --out-bin <path>  write raw u64 tsc stream\n",
          argv0);
}

static int parse_u64(const char *s, uint64_t *v) {
  char *end = NULL;
  errno = 0;
  unsigned long long x = strtoull(s, &end, 0);
  if (errno != 0 || end == s || *end != '\0')
    return -1;
  *v = (uint64_t)x;
  return 0;
}

static int parse_u32(const char *s, uint32_t *v) {
  uint64_t t = 0;
  if (parse_u64(s, &t) != 0 || t > 0xFFFFFFFFULL)
    return -1;
  *v = (uint32_t)t;
  return 0;
}

static int connect_unix(const char *sock_path) {
  int fd;
  struct sockaddr_un addr;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(sock_path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int main(int argc, char **argv) {
  struct opts o;
  int fd = -1;
  FILE *csv = NULL;
  FILE *bin = NULL;
  uint64_t global_min = UINT64_MAX, global_max = 0, global_sum = 0, global_n = 0;

  memset(&o, 0, sizeof(o));
  o.mode = 2;
  o.samples = 1024;
  o.rounds = 1;
  o.sleep_us = 0;
  o.flags = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) {
      o.sock_path = argv[++i];
    } else if (strcmp(argv[i], "--gpa") == 0 && i + 1 < argc) {
      if (parse_u64(argv[++i], &o.gpa) != 0) {
        fprintf(stderr, "invalid --gpa\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &o.mode) != 0) {
        fprintf(stderr, "invalid --mode\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &o.samples) != 0 || o.samples == 0) {
        fprintf(stderr, "invalid --samples\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &o.rounds) != 0 || o.rounds == 0) {
        fprintf(stderr, "invalid --rounds\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--sleep-us") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &o.sleep_us) != 0) {
        fprintf(stderr, "invalid --sleep-us\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--flags") == 0 && i + 1 < argc) {
      if (parse_u64(argv[++i], &o.flags) != 0) {
        fprintf(stderr, "invalid --flags\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--out-csv") == 0 && i + 1 < argc) {
      o.out_csv = argv[++i];
    } else if (strcmp(argv[i], "--out-bin") == 0 && i + 1 < argc) {
      o.out_bin = argv[++i];
    } else {
      usage(argv[0]);
      return 2;
    }
  }

  if (!o.sock_path || o.gpa == 0) {
    usage(argv[0]);
    return 2;
  }

  fd = connect_unix(o.sock_path);
  if (fd < 0) {
    fprintf(stderr, "connect(%s) failed: errno=%d\n", o.sock_path, errno);
    return 1;
  }

  if (o.out_csv) {
    csv = fopen(o.out_csv, "w");
    if (!csv) {
      fprintf(stderr, "fopen(%s) failed: errno=%d\n", o.out_csv, errno);
      close(fd);
      return 1;
    }
    fprintf(csv, "round,idx,tsc\n");
  }
  if (o.out_bin) {
    bin = fopen(o.out_bin, "wb");
    if (!bin) {
      fprintf(stderr, "fopen(%s) failed: errno=%d\n", o.out_bin, errno);
      if (csv)
        fclose(csv);
      close(fd);
      return 1;
    }
  }

  for (uint32_t r = 0; r < o.rounds; r++) {
    struct nptctl_req req;
    struct nptctl_resp resp;
    uint64_t *buf = NULL;
    uint64_t round_min = UINT64_MAX, round_max = 0, round_sum = 0;
    uint64_t got = 0;

    memset(&req, 0, sizeof(req));
    req.magic = NPTCTL_MAGIC;
    req.cmd = NPTCTL_CMD_READ_GPA_BATCH;
    req.a = o.gpa;
    req.b = o.mode;
    req.c = o.samples;
    req.d = o.flags;

    if (write_full(fd, &req, sizeof(req)) != 0) {
      fprintf(stderr, "write req failed: errno=%d\n", errno);
      goto fail;
    }
    if (read_full(fd, &resp, sizeof(resp)) <= 0) {
      fprintf(stderr, "read resp failed: errno=%d\n", errno);
      goto fail;
    }
    if (resp.magic != NPTCTL_MAGIC || resp.cmd != NPTCTL_CMD_READ_GPA_BATCH) {
      fprintf(stderr, "bad resp magic/cmd\n");
      goto fail;
    }
    if (resp.status != 0) {
      fprintf(stderr, "nptctl error: errno=%d kret=%d\n", resp.sys_errno, resp.kret);
      goto fail;
    }
    if (resp.kret != 0) {
      fprintf(stderr, "kernel kret=%d\n", resp.kret);
      goto fail;
    }

    got = resp.v0;
    buf = (uint64_t *)malloc((size_t)got * sizeof(uint64_t));
    if (!buf) {
      fprintf(stderr, "malloc failed\n");
      goto fail;
    }
    if (got > 0 && read_full(fd, buf, (size_t)got * sizeof(uint64_t)) <= 0) {
      fprintf(stderr, "read payload failed: errno=%d\n", errno);
      free(buf);
      goto fail;
    }

    for (uint64_t i = 0; i < got; i++) {
      uint64_t t = buf[i];
      if (t < round_min)
        round_min = t;
      if (t > round_max)
        round_max = t;
      round_sum += t;
      if (csv)
        fprintf(csv, "%" PRIu32 ",%" PRIu64 ",%" PRIu64 "\n", r, i, t);
    }
    if (bin && got > 0)
      fwrite(buf, sizeof(uint64_t), (size_t)got, bin);
    free(buf);

    if (got > 0) {
      double mean = (double)round_sum / (double)got;
      fprintf(stdout, "round=%u samples=%" PRIu64 " mean=%.3f min=%" PRIu64 " max=%" PRIu64 "\n",
              r, got, mean, round_min, round_max);
      if (round_min < global_min)
        global_min = round_min;
      if (round_max > global_max)
        global_max = round_max;
      global_sum += round_sum;
      global_n += got;
    }

    if (o.sleep_us > 0 && r + 1 < o.rounds)
      usleep(o.sleep_us);
  }

  if (global_n > 0) {
    fprintf(stdout, "overall samples=%" PRIu64 " mean=%.3f min=%" PRIu64 " max=%" PRIu64 "\n",
            global_n, (double)global_sum / (double)global_n, global_min, global_max);
  }

  if (csv)
    fclose(csv);
  if (bin)
    fclose(bin);
  close(fd);
  return 0;

fail:
  if (csv)
    fclose(csv);
  if (bin)
    fclose(bin);
  close(fd);
  return 1;
}
