#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

#include "host_runner_preload_shared.h"

static int parse_cmdline_value(const char *cmdline, const char *key, char *out,
                               size_t out_sz) {
  const char *p = strstr(cmdline, key);
  const char *end;
  size_t len;

  if (!p)
    return -1;
  p += strlen(key);
  end = p;
  while (*end && !isspace((unsigned char)*end))
    end++;
  len = (size_t)(end - p);
  if (len + 1 > out_sz)
    return -1;
  memcpy(out, p, len);
  out[len] = '\0';
  return 0;
}

static int read_cmdline(char *buf, size_t buf_sz) {
  FILE *fp = fopen("/proc/cmdline", "r");
  if (!fp)
    return -1;
  if (!fgets(buf, (int)buf_sz, fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

static int guest_pfn_for_va(uintptr_t va, uint64_t *pfn_out) {
  uint64_t entry = 0;
  off_t index = (off_t)((va / PAGE_SZ) * sizeof(uint64_t));
  int fd = open("/proc/self/pagemap", O_RDONLY);
  ssize_t r;

  if (fd < 0) {
    fprintf(stderr, "[guest_probe] pagemap open failed: %s\n", strerror(errno));
    return -1;
  }
  r = pread(fd, &entry, sizeof(entry), index);
  close(fd);

  if (r != (ssize_t)sizeof(entry)) {
    fprintf(stderr, "[guest_probe] pagemap pread(%lld) returned %zd: %s\n",
            (long long)index, r, strerror(errno));
    return -1;
  }
  if ((entry & (1ULL << 63)) == 0) {
    fprintf(stderr, "[guest_probe] pagemap: entry=0x%016llx page NOT present\n",
            (unsigned long long)entry);
    return -1;
  }
  *pfn_out = entry & ((1ULL << 55) - 1);
  return 0;
}

static void init_page_pair_data(uint8_t *page, uint8_t *page2) {
  for (size_t i = 0; i < PAGE_SZ; i += LINE_SZ) {
    page[i] = (uint8_t)(i / LINE_SZ);
    page2[i] = (uint8_t)(0x80U + (uint8_t)(i / LINE_SZ));
  }
}

static int alloc_page_pair(uint8_t **page_out, uint8_t **page2_out,
                           uint64_t *pfn_out, uint64_t *pfn2_out,
                           int require_contig) {
  if (!require_contig) {
    uint8_t *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *page2 = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || page2 == MAP_FAILED) {
      if (page != MAP_FAILED)
        munmap(page, PAGE_SZ);
      if (page2 != MAP_FAILED)
        munmap(page2, PAGE_SZ);
      return -1;
    }
    (void)mlock(page, PAGE_SZ);
    (void)mlock(page2, PAGE_SZ);

    init_page_pair_data(page, page2);
    if (guest_pfn_for_va((uintptr_t)page, pfn_out) != 0 ||
        guest_pfn_for_va((uintptr_t)page2, pfn2_out) != 0) {
      munmap(page, PAGE_SZ);
      munmap(page2, PAGE_SZ);
      return -1;
    }
    *page_out = page;
    *page2_out = page2;
    return 0;
  }

  for (int attempt = 0; attempt < 256; attempt++) {
    uint8_t *base = mmap(NULL, 2 * PAGE_SZ, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *page;
    uint8_t *page2;
    uint64_t pfn = 0, pfn2 = 0;
    if (base == MAP_FAILED)
      return -1;

    (void)mlock(base, 2 * PAGE_SZ);
    page = base;
    page2 = base + PAGE_SZ;
    init_page_pair_data(page, page2);
    if (guest_pfn_for_va((uintptr_t)page, &pfn) == 0 &&
        guest_pfn_for_va((uintptr_t)page2, &pfn2) == 0 && pfn2 == pfn + 1) {
      *page_out = page;
      *page2_out = page2;
      *pfn_out = pfn;
      *pfn2_out = pfn2;
      return 0;
    }
    munmap(base, 2 * PAGE_SZ);
  }
  return -1;
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

static const char *normalize_mode(const char *mode) {
  if (strcmp(mode, "sync") == 0)
    return "sync";
  if (strcmp(mode, "sync_all") == 0)
    return "sync_all";
  if (strcmp(mode, "cipher_toggle") == 0)
    return "cipher_toggle";
  if (strcmp(mode, "contention") == 0)
    return "contention";
  if (strcmp(mode, "contention_spatial") == 0)
    return "contention_spatial";
  if (strcmp(mode, "blind") == 0)
    return "blind";
  if (strcmp(mode, "hammer64") == 0)
    return "hammer64";
  if (strcmp(mode, "idle") == 0)
    return "idle";
  if (strcmp(mode, "pc") == 0)
    return "pc";
  if (strcmp(mode, "contention_blind") == 0)
    return "contention_blind";
  return mode;
}

static inline uint64_t signal_host(volatile struct sync_mailbox *mb) {
  return __atomic_add_fetch((uint64_t *)&mb->guest_seq, 1ULL, __ATOMIC_SEQ_CST);
}

static inline void wait_host_ack(volatile struct sync_mailbox *mb,
                                 uint64_t seq) {
  while (__atomic_load_n((uint64_t *)&mb->host_seq, __ATOMIC_ACQUIRE) < seq) {
    __builtin_ia32_pause();
  }
}

static inline void sleep_us(uint64_t us) {
  if (us == 0)
    return;
  struct timespec ts = {
      .tv_sec = (time_t)(us / 1000000ULL),
      .tv_nsec = (long)(us % 1000000ULL) * 1000L,
  };
  nanosleep(&ts, NULL);
}

static inline void guest_sync_round(volatile struct sync_mailbox *mb,
                                    volatile uint8_t *addr) {
  (void)*addr;
  __asm__ __volatile__("" ::: "memory");
  uint64_t seq = signal_host(mb);
  wait_host_ack(mb, seq);
}

static inline uint64_t signal_phase(volatile struct sync_mailbox *mb) {
  return __atomic_add_fetch((uint64_t *)&mb->phase_seq, 1ULL,
                            __ATOMIC_SEQ_CST);
}

static inline void wait_phase_ack(volatile struct sync_mailbox *mb,
                                  uint64_t seq) {
  while (__atomic_load_n((uint64_t *)&mb->phase_ack, __ATOMIC_ACQUIRE) < seq) {
    __builtin_ia32_pause();
  }
}

static inline uint64_t signal_cfg_ready(volatile struct sync_mailbox *mb) {
  return __atomic_add_fetch((uint64_t *)&mb->cfg_ready_seq, 1ULL,
                            __ATOMIC_SEQ_CST);
}

static inline void wait_cfg_ack(volatile struct sync_mailbox *mb, uint64_t seq) {
  while (__atomic_load_n((uint64_t *)&mb->cfg_ack_seq, __ATOMIC_ACQUIRE) < seq) {
    __builtin_ia32_pause();
  }
}

static inline void publish_cfg(volatile struct sync_mailbox *mb,
                               uint64_t mode_id, uint64_t target_gpa,
                               uint64_t other_gpa, uint64_t page_gpa,
                               uint64_t shared_gpa, uint64_t dec_line,
                               uint64_t flags, uint64_t host_lines,
                               uint64_t reps, uint64_t aux0, uint64_t aux1) {
  __atomic_store_n((uint64_t *)&mb->cfg_mode, mode_id, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_target_gpa, target_gpa,
                   __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_other_gpa, other_gpa,
                   __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_page_gpa, page_gpa, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_shared_gpa, shared_gpa,
                   __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_dec_line, dec_line, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_flags, flags, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_reserved0, 0ULL, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_host_lines, host_lines,
                   __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_reps, reps, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_aux0, aux0, __ATOMIC_RELEASE);
  __atomic_store_n((uint64_t *)&mb->cfg_aux1, aux1, __ATOMIC_RELEASE);
  {
    uint64_t seq = signal_cfg_ready(mb);
    wait_cfg_ack(mb, seq);
  }
}

int main(void) {
  char cmdline[2048] = {0};
  char mode_raw[64] = "sync";
  char tmp[64];
  const char *mode;
  int dec_line = 0;
  unsigned sync_port = 0xe9;
  int debugcon_ok = 0;
  uint8_t *page;
  uint8_t *page2;
  volatile uint8_t *target;
  uint64_t pfn = 0;
  uint64_t pfn2 = 0;
  uint64_t gpa = 0;
  uint64_t gpa2 = 0;
  uint64_t target_gpa = 0;
  uint64_t other_page_gpa = 0;
  uint64_t line_mask = ~0ULL;
  uint64_t sync_all_reps = 32;
  uint64_t sync_all_host_lines = 64;
  uint64_t toggle_iters = 12;
  uint64_t toggle_delay_us = 100000;
  char toggle_flush[16] = "line";
  const uint64_t pc_pause_us = 200;
  const uint64_t contention_pause_us = 1;
  int measure_other_page = 1;
  int require_contig_pair = 0;
  int host_target_page_mode = 0; /* 0=primary, 1=secondary, 2=follow_kind */
  struct timespec ts_1s = {.tv_sec = 1, .tv_nsec = 0};

  if (read_cmdline(cmdline, sizeof(cmdline)) == 0) {
    if (parse_cmdline_value(cmdline, "probe_mode=", mode_raw,
                            sizeof(mode_raw)) != 0)
      strcpy(mode_raw, "sync");
    if (parse_cmdline_value(cmdline, "probe_dec_line=", tmp, sizeof(tmp)) == 0)
      dec_line = atoi(tmp);
    if (parse_cmdline_value(cmdline, "probe_sync_port=", tmp, sizeof(tmp)) == 0)
      sync_port = (unsigned)strtoul(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_line_mask=", tmp, sizeof(tmp)) == 0)
      line_mask = strtoull(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_measure_other=", tmp,
                            sizeof(tmp)) == 0)
      measure_other_page = atoi(tmp) != 0;
    if (parse_cmdline_value(cmdline, "probe_phase_active_reps=", tmp,
                            sizeof(tmp)) == 0)
      sync_all_reps = strtoull(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_host_lines=", tmp, sizeof(tmp)) ==
        0)
      sync_all_host_lines = strtoull(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_toggle_iters=", tmp, sizeof(tmp)) ==
        0)
      toggle_iters = strtoull(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_toggle_delay_us=", tmp,
                            sizeof(tmp)) == 0)
      toggle_delay_us = strtoull(tmp, NULL, 0);
    if (parse_cmdline_value(cmdline, "probe_toggle_flush=", toggle_flush,
                            sizeof(toggle_flush)) != 0)
      strcpy(toggle_flush, "line");
    if (parse_cmdline_value(cmdline, "probe_contig_pair=", tmp, sizeof(tmp)) ==
        0)
      require_contig_pair = atoi(tmp) != 0;
    if (parse_cmdline_value(cmdline, "probe_host_target_page=", tmp,
                            sizeof(tmp)) == 0) {
      if (strcmp(tmp, "secondary") == 0 || strcmp(tmp, "1") == 0)
        host_target_page_mode = 1;
      else if (strcmp(tmp, "follow_kind") == 0 || strcmp(tmp, "2") == 0)
        host_target_page_mode = 2;
      else
        host_target_page_mode = 0;
    }
  }

  mode = normalize_mode(mode_raw);

  if (dec_line < 0 || dec_line >= (int)(PAGE_SZ / LINE_SZ)) {
    fprintf(stderr, "[guest_probe] invalid probe_dec_line=%d\n", dec_line);
    return 1;
  }
  if (sync_all_host_lines == 0 || sync_all_host_lines > (PAGE_SZ / LINE_SZ))
    sync_all_host_lines = PAGE_SZ / LINE_SZ;

  if (alloc_page_pair(&page, &page2, &pfn, &pfn2, require_contig_pair) != 0) {
    fprintf(stderr, "[guest_probe] failed to allocate %s page pair\n",
            require_contig_pair ? "physically-contiguous" : "page");
    return 1;
  }

  gpa = pfn * PAGE_SZ;
  gpa2 = pfn2 * PAGE_SZ;
  target = page + ((size_t)dec_line * LINE_SZ);
  target_gpa = gpa + (uint64_t)dec_line * LINE_SZ;
  other_page_gpa = gpa2 + (uint64_t)dec_line * LINE_SZ;

  if (debugcon_init(sync_port) == 0)
    debugcon_ok = 1;

  printf("SNP_PROBE GPA=0x%llx PAGE_GPA=0x%llx OTHER_PAGE_GPA=0x%llx "
         "DEC_LINE=%d MODE=%s\n",
         (unsigned long long)target_gpa, (unsigned long long)gpa,
         (unsigned long long)gpa2, dec_line, mode);
  fflush(stdout);
  if (debugcon_ok) {
    debugcon_printf(sync_port,
                    "SNP_PROBE GPA=0x%llx PAGE_GPA=0x%llx "
                    "OTHER_PAGE_GPA=0x%llx DEC_LINE=%d MODE=%s\n",
                    (unsigned long long)target_gpa, (unsigned long long)gpa,
                    (unsigned long long)gpa2, dec_line, mode);
  }
  if (debugcon_ok) {
    debugcon_printf(
        sync_port, "SNP_PAGE_PAIR CONTIG=%d PFN0=0x%llx PFN1=0x%llx\n",
        require_contig_pair, (unsigned long long)pfn, (unsigned long long)pfn2);
  }

  int snp_fd = open("/dev/snp_sync", O_RDWR);
  volatile struct sync_mailbox *shared_mem = NULL;
  uint64_t shared_gpa = 0;
  if (snp_fd >= 0) {
    if (ioctl(snp_fd, _IOR(0xB3u, 0x01, uint64_t), &shared_gpa) == 0) {
      void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, snp_fd, 0);
      if (m != MAP_FAILED) {
        shared_mem = (volatile struct sync_mailbox *)m;
        __atomic_store_n((uint64_t *)&shared_mem->guest_seq, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->host_seq, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_seq, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_ack, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_kind, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_vline, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_target_gpa, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_done, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_magic,
                         SYNC_MAILBOX_MAGIC, __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_ready_seq, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_ack_seq, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_mode, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_target_gpa, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_other_gpa, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_page_gpa, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_shared_gpa, shared_gpa,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_dec_line, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_flags, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_reserved0, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_host_lines, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_reps, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_aux0, 0ULL,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->cfg_aux1, 0ULL,
                         __ATOMIC_RELEASE);
        __asm__ __volatile__("sfence" ::: "memory");
      }
    }
  }

  if ((strcmp(mode, "sync") == 0 || strcmp(mode, "sync_all") == 0 ||
       strcmp(mode, "contention") == 0 || strcmp(mode, "contention_spatial") == 0 ||
       strcmp(mode, "pc") == 0 ||
       strcmp(mode, "cipher_toggle") == 0) &&
      !shared_mem) {
    fprintf(
        stderr,
        "[guest_probe] shared sync (/dev/snp_sync) is required for mode=%s\n",
        mode);
    return 1;
  }

  if (strcmp(mode, "idle") == 0) {
    for (;;)
      nanosleep(&ts_1s, NULL);
  }

  if (strcmp(mode, "cipher_toggle") == 0) {
    uint64_t flush_code = 0;
    struct timespec toggle_sleep = {
        .tv_sec = (time_t)(toggle_delay_us / 1000000ULL),
        .tv_nsec = (long)(toggle_delay_us % 1000000ULL) * 1000L,
    };
    if (strcmp(toggle_flush, "line") == 0)
      flush_code = 1;
    else if (strcmp(toggle_flush, "page") == 0)
      flush_code = 2;

    printf("SNP_PROBE CIPHER_TOGGLE page_gpa=0x%llx line=%d line_gpa=0x%llx "
           "iters=%llu delay_us=%llu flush=%s\n",
           (unsigned long long)gpa, dec_line, (unsigned long long)target_gpa,
           (unsigned long long)toggle_iters,
           (unsigned long long)toggle_delay_us, toggle_flush);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(sync_port,
                      "SNP_PROBE CIPHER_TOGGLE page_gpa=0x%llx line=%d "
                      "line_gpa=0x%llx iters=%llu delay_us=%llu flush=%s\n",
                      (unsigned long long)gpa, dec_line,
                      (unsigned long long)target_gpa,
                      (unsigned long long)toggle_iters,
                      (unsigned long long)toggle_delay_us, toggle_flush);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_TOGGLE, target_gpa, other_page_gpa,
                gpa, shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, toggle_iters,
                toggle_delay_us, 0ULL);
    if (shared_mem) {
      publish_cfg(shared_mem, SYNC_CFG_MODE_TOGGLE, target_gpa, other_page_gpa,
                  gpa, shared_gpa, (uint64_t)dec_line, flush_code, 0ULL,
                  toggle_iters, toggle_delay_us, 0ULL);
    }

    for (uint64_t seq = 0; seq < toggle_iters; seq++) {
      unsigned fill = (seq & 1ULL) ? 0xffU : 0x00U;
      char state = (seq & 1ULL) ? 'B' : 'A';

      memset((void *)target, (int)fill, LINE_SZ);
      __asm__ __volatile__("" ::: "memory");
#if defined(__x86_64__)
      if (strcmp(toggle_flush, "line") == 0) {
        _mm_clflush((const void *)target);
      } else if (strcmp(toggle_flush, "page") == 0) {
        for (size_t li = 0; li < (PAGE_SZ / LINE_SZ); li++)
          _mm_clflush((const void *)(page + li * LINE_SZ));
      }
      _mm_mfence();
#endif

      if (debugcon_ok) {
        debugcon_printf(sync_port,
                        "SNP_TOGGLE seq=%llu state=%c line=%d line_gpa=0x%llx "
                        "fill=0x%02x flush=%s\n",
                        (unsigned long long)seq, state, dec_line,
                        (unsigned long long)target_gpa, fill, toggle_flush);
      }

      if (toggle_delay_us > 0)
        nanosleep(&toggle_sleep, NULL);
    }

    if (debugcon_ok)
      debugcon_printf(sync_port, "SNP_TOGGLE_DONE seq=%llu\n",
                      (unsigned long long)toggle_iters);

    for (;;)
      nanosleep(&ts_1s, NULL);
  }

  if (strcmp(mode, "sync") == 0) {
    printf("SNP_PROBE SYNC target_gpa=0x%llx other_page_gpa=0x%llx "
           "shared_gpa=0x%llx\n",
           (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
           (unsigned long long)shared_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE SYNC target_gpa=0x%llx other_page_gpa=0x%llx "
          "shared_gpa=0x%llx\n",
          (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
          (unsigned long long)shared_gpa);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_SYNC, target_gpa, other_page_gpa, gpa,
                shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL);
    for (;;) {
      guest_sync_round(shared_mem, target);
    }
  }

  if (strcmp(mode, "pc") == 0) {
    /* Prime+Count: odd seq -> target, even seq -> other_page. */
    volatile uint8_t *other_line = page2 + (size_t)dec_line * LINE_SZ;

    printf("SNP_PROBE PC target_gpa=0x%llx other_page_gpa=0x%llx pc_pause_us=%llu "
           "shared_gpa=0x%llx\n",
           (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
           (unsigned long long)pc_pause_us, (unsigned long long)shared_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE PC target_gpa=0x%llx other_page_gpa=0x%llx pc_pause_us=%llu "
          "shared_gpa=0x%llx\n",
          (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
          (unsigned long long)pc_pause_us, (unsigned long long)shared_gpa);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_PC, target_gpa, other_page_gpa, gpa,
                shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, 0ULL, pc_pause_us,
                0ULL);

    for (int parity = 0;; parity ^= 1) {
      if (parity == 0) {
        (void)*target; /* H1: 访问 target，可能驱逐 host eviction set */
      } else {
        (void)*other_line; /* H0: 访问 other_page，不与 evset 冲突 */
      }
      __asm__ __volatile__("" ::: "memory");
      {
        uint64_t seq = signal_host(shared_mem);
        wait_host_ack(shared_mem, seq);
      }
      sleep_us(pc_pause_us);
    }
  }

  if (strcmp(mode, "sync_all") == 0) {
    if (sync_all_reps == 0)
      sync_all_reps = 32;

    printf("SNP_PROBE SYNC_ALL page_gpa=0x%llx other_page_gpa=0x%llx "
           "host_reps=%llu shared_gpa=0x%llx\n",
           (unsigned long long)gpa, (unsigned long long)gpa2,
           (unsigned long long)sync_all_reps, (unsigned long long)shared_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE SYNC_ALL page_gpa=0x%llx other_page_gpa=0x%llx "
          "host_reps=%llu shared_gpa=0x%llx\n",
          (unsigned long long)gpa, (unsigned long long)gpa2,
          (unsigned long long)sync_all_reps, (unsigned long long)shared_gpa);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_SYNC_ALL, target_gpa, other_page_gpa,
                gpa, shared_gpa, (uint64_t)dec_line,
                (uint64_t)measure_other_page, sync_all_host_lines, sync_all_reps,
                (uint64_t)host_target_page_mode, 0ULL);

    for (int kind = 0; kind < 2; kind++) {
      if (kind == 1 && !measure_other_page)
        continue;

      uint64_t base_gpa = (kind == 0) ? gpa : gpa2;
      volatile uint8_t *base_page = (kind == 0) ? page : page2;

      for (int vline = 0; vline < 64; vline++) {
        if ((line_mask & (1ULL << vline)) == 0)
          continue;

        volatile uint8_t *target_line_ptr = base_page + (size_t)vline * LINE_SZ;
        uint64_t host_target_gpa = gpa;
        if (host_target_page_mode == 1)
          host_target_gpa = gpa2;
        else if (host_target_page_mode == 2)
          host_target_gpa = base_gpa;

        if (debugcon_ok) {
          debugcon_printf(sync_port,
                          "SNP_VLINE kind=%d line=%d target_gpa=0x%llx\n", kind,
                          vline, (unsigned long long)host_target_gpa);
        }

        __atomic_store_n((uint64_t *)&shared_mem->phase_kind, (uint64_t)kind,
                         __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_vline,
                         (uint64_t)vline, __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_target_gpa,
                         (uint64_t)host_target_gpa, __ATOMIC_RELEASE);
        __atomic_store_n((uint64_t *)&shared_mem->phase_done, 0ULL,
                         __ATOMIC_RELEASE);
        {
          uint64_t phase_seq = signal_phase(shared_mem);
          wait_phase_ack(shared_mem, phase_seq);
        }

        uint64_t total_syncs = sync_all_host_lines * sync_all_reps;
        for (uint64_t i = 0; i < total_syncs; i++) {
          guest_sync_round(shared_mem, target_line_ptr);
        }
      }
    }

    __atomic_store_n((uint64_t *)&shared_mem->phase_kind, SYNC_PHASE_DONE,
                     __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&shared_mem->phase_vline, 0ULL,
                     __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&shared_mem->phase_target_gpa, 0ULL,
                     __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&shared_mem->phase_done, 1ULL,
                     __ATOMIC_RELEASE);
    {
      uint64_t phase_seq = signal_phase(shared_mem);
      wait_phase_ack(shared_mem, phase_seq);
    }

    if (debugcon_ok)
      debugcon_printf(sync_port, "SNP_PROBE_ALL_DONE\n");
    for (;;)
      nanosleep(&ts_1s, NULL);
  }

  if (strcmp(mode, "contention") == 0) {
    /* DRAM row-buffer contention path used by exp42b (NOCACHE). */
    printf("SNP_PROBE CONTENTION target_gpa=0x%llx other_page_gpa=0x%llx "
           "contention_pause_us=%llu shared_gpa=0x%llx\n",
           (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
           (unsigned long long)contention_pause_us, (unsigned long long)shared_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE CONTENTION target_gpa=0x%llx other_page_gpa=0x%llx "
          "contention_pause_us=%llu shared_gpa=0x%llx\n",
          (unsigned long long)target_gpa, (unsigned long long)other_page_gpa,
          (unsigned long long)contention_pause_us, (unsigned long long)shared_gpa);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_CONTENTION, target_gpa, other_page_gpa,
                gpa, shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, 0ULL,
                contention_pause_us, 0ULL);

    for (;;) {
      /* Step 1: evict target from LLC so the next load comes from DRAM */
#if defined(__x86_64__)
      _mm_clflush((void *)target);
      _mm_mfence();
#endif

      /* Step 2: load target from DRAM, activating its DRAM row */
      (void)*target;
      __asm__ __volatile__("" ::: "memory");

      /* Step 3: notify host and keep hammering until ACK arrives.
       * This turns [signal_host, host_ack] into the actual contention window,
       * increasing the chance that the host probe overlaps guest traffic. */
      {
        uint64_t seq = signal_host(shared_mem);
        while (__atomic_load_n((uint64_t *)&shared_mem->host_seq,
                               __ATOMIC_ACQUIRE) < seq) {
#if defined(__x86_64__)
          _mm_clflush((void *)target);
          _mm_mfence();
#endif
          (void)*target;
          __asm__ __volatile__("" ::: "memory");
          __builtin_ia32_pause();
        }
      }

      sleep_us(contention_pause_us);
    }
  }

  if (strcmp(mode, "contention_spatial") == 0) {
    printf("SNP_PROBE CONTENTION_SPATIAL target_gpa=0x%llx page_gpa=0x%llx "
           "victim_line=%d shared_gpa=0x%llx pause_us=%llu\n",
           (unsigned long long)target_gpa, (unsigned long long)gpa, dec_line,
           (unsigned long long)shared_gpa,
           (unsigned long long)contention_pause_us);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE CONTENTION_SPATIAL target_gpa=0x%llx page_gpa=0x%llx "
          "victim_line=%d shared_gpa=0x%llx pause_us=%llu\n",
          (unsigned long long)target_gpa, (unsigned long long)gpa, dec_line,
          (unsigned long long)shared_gpa,
          (unsigned long long)contention_pause_us);
    }
    publish_cfg(shared_mem, SYNC_CFG_MODE_CONTENTION_SPATIAL, target_gpa,
                other_page_gpa, gpa, shared_gpa, (uint64_t)dec_line, 0ULL,
                LINES, 0ULL, contention_pause_us, 0ULL);

    for (;;) {
#if defined(__x86_64__)
      _mm_clflush((void *)target);
      _mm_mfence();
#endif
      (void)*target;
      __asm__ __volatile__("" ::: "memory");
      {
        uint64_t seq = signal_host(shared_mem);
        while (__atomic_load_n((uint64_t *)&shared_mem->host_seq,
                               __ATOMIC_ACQUIRE) < seq) {
#if defined(__x86_64__)
          _mm_clflush((void *)target);
          _mm_mfence();
#endif
          (void)*target;
          __asm__ __volatile__("" ::: "memory");
          __builtin_ia32_pause();
        }
      }
      sleep_us(contention_pause_us);
    }
  }

  if (strcmp(mode, "blind") == 0) {
    /* Blind concurrent mode: guest hammers target while host probes blindly. */
    printf("SNP_PROBE BLIND target_gpa=0x%llx other_page_gpa=0x%llx\n",
           (unsigned long long)target_gpa, (unsigned long long)other_page_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE BLIND target_gpa=0x%llx other_page_gpa=0x%llx\n",
          (unsigned long long)target_gpa, (unsigned long long)other_page_gpa);
    }
    for (;;) {
      (void)*target;
      __asm__ __volatile__("" ::: "memory");
    }
  }

  if (strcmp(mode, "contention_blind") == 0) {
    /* Contention-blind mode: guest does CLFLUSH+load in tight loop (no sync).
     * Used by exp 4.2.3.2 H1_cmb: provides both coherence and contention
     * signals when host probes with CIPHERTEXT_CACHEABLE (no pre-clflush). */
    printf("SNP_PROBE CONTENTION_BLIND target_gpa=0x%llx other_page_gpa=0x%llx\n",
           (unsigned long long)target_gpa, (unsigned long long)other_page_gpa);
    fflush(stdout);
    if (debugcon_ok) {
      debugcon_printf(
          sync_port,
          "SNP_PROBE CONTENTION_BLIND target_gpa=0x%llx other_page_gpa=0x%llx\n",
          (unsigned long long)target_gpa, (unsigned long long)other_page_gpa);
    }
    for (;;) {
#if defined(__x86_64__)
      _mm_clflush((void *)target);
      _mm_mfence();
#endif
      (void)*target;
      __asm__ __volatile__("" ::: "memory");
    }
  }

  if (strcmp(mode, "hammer64") == 0) {
    for (;;) {
      for (size_t li = 0; li < (PAGE_SZ / LINE_SZ); li++) {
        volatile uint8_t *p = page + li * LINE_SZ;
        (void)*p;
        __asm__ __volatile__("" ::: "memory");
      }
    }
  }

  fprintf(stderr, "[guest_probe] unsupported probe_mode=%s\n", mode_raw);
  return 1;
}
