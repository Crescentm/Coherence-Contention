#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

#include <openssl/aes.h>
#include "host_runner_preload_shared.h"
#include "kmod_guest/snp_sync_ioctl.h"

#define DEFAULT_TE0_FILE_OFFSET 0x8de0ULL
#define DEBUGCON_PORT 0xe9U

struct victim_args {
  int port;
  int sync_port;
  int oracle_print_te0_gpa;
  int sync_mailbox;
  int sync_gadget_te0;
  int sync_byte_pos;
  uint64_t te0_file_offset;
  uint64_t te0_vma;
};

struct victim_sync_ctx {
  int fd;
  uint64_t shared_gpa;
  volatile struct sync_mailbox *mb;
};

static int victim_sync_debug_enabled(void) {
  const char *env = getenv("VICTIM_SYNC_DEBUG");
  return env && atoi(env) != 0;
}

static int debugcon_init(unsigned port) {
  if (ioperm(port, 1, 1) != 0)
    return -1;
  return 0;
}

static void debugcon_puts(unsigned port, const char *s) {
  while (*s) {
#if defined(__x86_64__)
    __asm__ __volatile__("outb %b0, %w1" : : "a"((uint8_t)*s), "Nd"(port));
#endif
    s++;
  }
}

static void debugcon_printf(unsigned port, const char *fmt, ...) {
  char buf[512];
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n > 0)
    debugcon_puts(port, buf);
}

static inline uint64_t signal_host(volatile struct sync_mailbox *mb) {
  return __atomic_add_fetch((uint64_t *)&mb->guest_seq, 1ULL, __ATOMIC_SEQ_CST);
}

static inline int sync_host_ack_ready(volatile struct sync_mailbox *mb, uint64_t seq) {
  return __atomic_load_n((uint64_t *)&mb->host_seq, __ATOMIC_ACQUIRE) >= seq;
}

static uint32_t *resolve_te0_ptr(const struct victim_args *cfg) {
  Dl_info di;
  uintptr_t base = 0;
  uintptr_t te0_va = 0;

  if (!cfg)
    return NULL;
  if (cfg->te0_vma != 0) {
    te0_va = (uintptr_t)cfg->te0_vma;
  } else {
    memset(&di, 0, sizeof(di));
    if (dladdr((void *)AES_encrypt, &di) != 0 && di.dli_fbase) {
      base = (uintptr_t)di.dli_fbase;
    } else if (dladdr((void *)resolve_te0_ptr, &di) != 0 && di.dli_fbase) {
      base = (uintptr_t)di.dli_fbase;
    } else {
      return NULL;
    }
    te0_va = base + (uintptr_t)cfg->te0_file_offset;
  }
  return (uint32_t *)(uintptr_t)te0_va;
}

static void log_stderr_atomic(const char *msg) {
  size_t n;
  if (!msg)
    return;
  n = strlen(msg);
  while (n > 0) {
    ssize_t w = write(STDERR_FILENO, msg, n);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    msg += (size_t)w;
    n -= (size_t)w;
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

static uint64_t parse_u64_or_default(const char *s, uint64_t defv) {
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 0);
  if (end == s || (end && *end != '\0'))
    return defv;
  return (uint64_t)v;
}

static struct victim_args parse_args(int argc, char **argv) {
  struct victim_args out = {
    .port = 9000,
    .sync_port = 9002,
    .oracle_print_te0_gpa = 0,
    .sync_mailbox = 0,
    .sync_gadget_te0 = 0,
    .sync_byte_pos = 0,
    .te0_file_offset = DEFAULT_TE0_FILE_OFFSET,
    .te0_vma = 0,
  };
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--port") == 0) {
      out.port = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "--sync-port") == 0) {
      out.sync_port = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "--oracle-te0-file-offset") == 0) {
      out.te0_file_offset = parse_u64_or_default(argv[i + 1], DEFAULT_TE0_FILE_OFFSET);
      i++;
    } else if (strcmp(argv[i], "--oracle-te0-vma") == 0) {
      out.te0_vma = parse_u64_or_default(argv[i + 1], 0);
      i++;
    } else if (strcmp(argv[i], "--sync-byte-pos") == 0) {
      out.sync_byte_pos = atoi(argv[i + 1]);
      i++;
    }
  }
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--oracle-print-te0-gpa") == 0) {
      out.oracle_print_te0_gpa = 1;
    } else if (strcmp(argv[i], "--sync-mailbox") == 0) {
      out.sync_mailbox = 1;
    } else if (strcmp(argv[i], "--sync-gadget-te0") == 0) {
      out.sync_gadget_te0 = 1;
    }
  }
  if (out.port <= 0 || out.port > 65535)
    out.port = 9000;
  if (out.sync_port <= 0 || out.sync_port > 65535 || out.sync_port == out.port)
    out.sync_port = out.port + 2;
  if (out.sync_byte_pos < 0 || out.sync_byte_pos > 15)
    out.sync_byte_pos = 0;
  return out;
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
  if (listen(fd, 64) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static void maybe_print_te0_gpa_oracle(const struct victim_args *cfg) {
  if (!cfg || !cfg->oracle_print_te0_gpa)
    return;

  Dl_info di;
  uintptr_t base = 0;
  uintptr_t te0_va = 0;
  int fd = -1;
  struct snp_sync_va_to_gpa req;

  if (cfg->te0_vma != 0) {
    te0_va = (uintptr_t)cfg->te0_vma;
    base = te0_va - (uintptr_t)cfg->te0_file_offset;
  } else {
    memset(&di, 0, sizeof(di));
    if (dladdr((void *)AES_encrypt, &di) != 0 && di.dli_fbase) {
      base = (uintptr_t)di.dli_fbase;
    } else if (dladdr((void *)maybe_print_te0_gpa_oracle, &di) != 0 &&
               di.dli_fbase) {
      base = (uintptr_t)di.dli_fbase;
    } else {
      log_stderr_atomic(
          "victim_aes_oracle: dladdr failed (static linking). "
          "use --oracle-te0-vma 0x...\n");
      return;
    }
    te0_va = base + (uintptr_t)cfg->te0_file_offset;
  }

  fd = open(SNP_SYNC_DEV, O_RDWR);
  if (fd < 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "victim_aes_oracle: open(%s) failed: %s\n",
             SNP_SYNC_DEV, strerror(errno));
    log_stderr_atomic(msg);
    return;
  }

  memset(&req, 0, sizeof(req));
  req.va = (uint64_t)te0_va;
  if (ioctl(fd, SNP_SYNC_IOC_VA_TO_GPA, &req) != 0) {
    char msg[256];
    snprintf(msg, sizeof(msg), "victim_aes_oracle: ioctl(VA_TO_GPA) failed: %s\n",
             strerror(errno));
    log_stderr_atomic(msg);
    close(fd);
    return;
  }
  close(fd);

  if (req.ret != 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "victim_aes_oracle: VA_TO_GPA inner ret=%d\n", req.ret);
    log_stderr_atomic(msg);
    return;
  }

  {
    char msg[320];
    snprintf(
        msg, sizeof(msg),
        "victim_aes_oracle: aes_base=0x%lx te0_va=0x%lx te0_file_off=0x%llx te0_gpa=0x%llx te0_page_gpa=0x%llx\n",
        (unsigned long)base, (unsigned long)te0_va,
        (unsigned long long)cfg->te0_file_offset, (unsigned long long)req.gpa,
        (unsigned long long)(req.gpa & ~0xfffULL));
    log_stderr_atomic(msg);
  }
}

static int init_sync_ctx(struct victim_sync_ctx *ctx) {
  void *m = MAP_FAILED;

  if (!ctx)
    return -1;
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = open(SNP_SYNC_DEV, O_RDWR);
  if (ctx->fd < 0)
    return -1;
  if (ioctl(ctx->fd, SNP_SYNC_IOC_GET_GPA, &ctx->shared_gpa) != 0) {
    close(ctx->fd);
    ctx->fd = -1;
    return -1;
  }
  (void)debugcon_init(DEBUGCON_PORT);
  m = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->fd, 0);
  if (m == MAP_FAILED) {
    close(ctx->fd);
    ctx->fd = -1;
    return -1;
  }
  ctx->mb = (volatile struct sync_mailbox *)m;
  __atomic_store_n((uint64_t *)&ctx->mb->guest_seq, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->host_seq, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_seq, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_ack, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_kind, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_vline, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_target_gpa, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_done, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->phase_magic, SYNC_MAILBOX_MAGIC, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->cfg_ready_seq, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&ctx->mb->cfg_ack_seq, 0ULL, __ATOMIC_RELEASE);
  __asm__ __volatile__("sfence" ::: "memory");
  debugcon_printf(DEBUGCON_PORT, "SNP_PROBE VICTIM_AES shared_gpa=0x%llx\n",
                  (unsigned long long)ctx->shared_gpa);
  return 0;
}

static void free_sync_ctx(struct victim_sync_ctx *ctx) {
  if (!ctx)
    return;
  if (ctx->mb)
    munmap((void *)ctx->mb, PAGE_SZ);
  if (ctx->fd >= 0)
    close(ctx->fd);
  ctx->fd = -1;
  ctx->mb = NULL;
  ctx->shared_gpa = 0;
}

int main(int argc, char **argv) {
  const uint8_t fixed_key[16] = {
      0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  };
  struct victim_args cfg = parse_args(argc, argv);
  struct victim_sync_ctx sync_ctx = {.fd = -1};
  AES_KEY aes_key;
  uint32_t *te0_ptr = NULL;
  volatile uint64_t sync_sink = 0;
  int port = cfg.port;
  int lfd = -1;
  int sync_lfd = -1;

  if (AES_set_encrypt_key(fixed_key, 128, &aes_key) != 0) {
    fprintf(stderr, "victim_aes: AES_set_encrypt_key failed\n");
    return 1;
  }

  lfd = setup_listener(port);
  if (lfd < 0) {
    fprintf(stderr, "victim_aes: listen failed on %d: %s\n", port,
            strerror(errno));
    return 1;
  }

  maybe_print_te0_gpa_oracle(&cfg);
  if (cfg.sync_gadget_te0) {
    te0_ptr = resolve_te0_ptr(&cfg);
    if (!te0_ptr) {
      fprintf(stderr, "victim_aes: failed to resolve Te0 pointer for sync gadget\n");
      close(lfd);
      return 1;
    }
    fprintf(stderr, "victim_aes: sync gadget=te0 byte_pos=%d te0_ptr=%p\n",
            cfg.sync_byte_pos, (void *)te0_ptr);
    fflush(stderr);
  }
  if (cfg.sync_mailbox) {
    sync_lfd = setup_listener(cfg.sync_port);
    if (sync_lfd < 0) {
      fprintf(stderr, "victim_aes: sync listen failed on %d: %s\n",
              cfg.sync_port, strerror(errno));
      free_sync_ctx(&sync_ctx);
      close(lfd);
      return 1;
    }
    if (init_sync_ctx(&sync_ctx) != 0) {
      fprintf(stderr, "victim_aes: sync mailbox init failed: %s\n",
              strerror(errno));
      close(sync_lfd);
      close(lfd);
      return 1;
    }
    fprintf(stderr,
            "victim_aes: sync mailbox enabled shared_gpa=0x%llx sync_port=%d\n",
            (unsigned long long)sync_ctx.shared_gpa, cfg.sync_port);
    fflush(stderr);
  }

  fprintf(stderr, "victim_aes: listening on 0.0.0.0:%d\n", port);
  fflush(stderr);

  for (;;) {
    int cfd = -1;
    int is_sync = 0;
    static uint64_t sync_req_count = 0;
    uint8_t plaintext[16], ciphertext[16];
    if (sync_lfd >= 0) {
      fd_set rfds;
      int maxfd = lfd > sync_lfd ? lfd : sync_lfd;
      FD_ZERO(&rfds);
      FD_SET(lfd, &rfds);
      FD_SET(sync_lfd, &rfds);
      if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
        if (errno == EINTR)
          continue;
        usleep(1000);
        continue;
      }
      if (FD_ISSET(sync_lfd, &rfds)) {
        cfd = accept(sync_lfd, NULL, NULL);
        is_sync = 1;
      } else if (FD_ISSET(lfd, &rfds)) {
        cfd = accept(lfd, NULL, NULL);
      }
    } else {
      cfd = accept(lfd, NULL, NULL);
    }
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      usleep(1000);
      continue;
    }

    if (readn(cfd, plaintext, sizeof(plaintext)) == (ssize_t)sizeof(plaintext)) {
      if (sync_ctx.mb && is_sync) {
        uint64_t seq = signal_host(sync_ctx.mb);
        sync_req_count++;
        if (victim_sync_debug_enabled() && sync_req_count <= 8) {
          fprintf(stderr, "victim_aes: sync req#%llu seq=%llu\n",
                  (unsigned long long)sync_req_count,
                  (unsigned long long)seq);
          fflush(stderr);
        }
        if (cfg.sync_gadget_te0 && te0_ptr) {
          uint8_t idx = plaintext[cfg.sync_byte_pos & 0xF];
          do {
            sync_sink ^= (uint64_t)te0_ptr[idx];
          } while (!sync_host_ack_ready(sync_ctx.mb, seq));
          memset(ciphertext, 0, sizeof(ciphertext));
          ciphertext[0] = idx;
          ciphertext[1] = (uint8_t)sync_sink;
        } else {
          do {
            AES_encrypt(plaintext, ciphertext, &aes_key);
          } while (!sync_host_ack_ready(sync_ctx.mb, seq));
        }
        if (victim_sync_debug_enabled() && sync_req_count <= 8) {
          fprintf(stderr, "victim_aes: sync req#%llu acked\n",
                  (unsigned long long)sync_req_count);
          fflush(stderr);
        }
      } else {
        AES_encrypt(plaintext, ciphertext, &aes_key);
      }
      (void)writen(cfd, ciphertext, sizeof(ciphertext));
    }
    close(cfd);
  }

  free_sync_ctx(&sync_ctx);
}
