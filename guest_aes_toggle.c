/* guest_aes_toggle.c — AES toggle guest for RRFS signal validation.
 *
 * Alternates between two groups of AES plaintexts:
 *   Group A: plaintext[0] in {0..7}   → accesses T0[0..7] → target cache line
 *   Group B: plaintext[0] in {128..255} → accesses T0[128..255] → different page
 *
 * After each AES call, writes group indicator to phase_kind, then signals
 * host via guest_seq and waits for host_seq ack.
 *
 * Build: see Makefile target guest_aes_toggle
 * Run via: probe_mode=aes_toggle kernel cmdline
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
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

#include <sys/io.h>

#include <openssl/aes.h>
#include "host_runner_preload_shared.h"
#include "kmod_guest/snp_sync_ioctl.h"

#define DEBUGCON_PORT 0xe9

static void debugcon_puts(const char *s) {
    while (*s)
        __asm__ __volatile__("outb %b0, %w1" : : "a"((uint8_t)*s++), "Nd"((uint16_t)DEBUGCON_PORT));
}

static void debugcon_printf(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    debugcon_puts(buf);
}

#define DEFAULT_TE0_FILE_OFFSET 0xf60ULL  /* T0 offset within libopenssl page */
#define DEFAULT_ITERS           2000ULL
#define GROUP_A_LABEL           0ULL
#define GROUP_B_LABEL           1ULL

#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t rdtscp64(void) {
    unsigned aux = 0;
    return __rdtscp(&aux);
}
#else
static inline uint64_t rdtscp64(void) { return 0; }
#endif

static const uint8_t FIXED_KEY[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

/* Group A: pt[0] in 0..7 → T0[0..7] → target cache line */
static const uint8_t GROUP_A_BYTES[8] = {0, 1, 2, 3, 4, 5, 6, 7};
/* Group B: pt[0] in 128..255 → T0[128..255] → different page */
static const uint8_t GROUP_B_BYTES[8] = {128, 144, 160, 176, 192, 208, 224, 240};

static inline uint64_t signal_host(volatile struct sync_mailbox *mb) {
    return __atomic_add_fetch((uint64_t *)&mb->guest_seq, 1ULL, __ATOMIC_SEQ_CST);
}

static inline void wait_host_ack(volatile struct sync_mailbox *mb, uint64_t seq) {
    while (__atomic_load_n((uint64_t *)&mb->host_seq, __ATOMIC_ACQUIRE) < seq)
        __builtin_ia32_pause();
}

static inline void publish_cfg(volatile struct sync_mailbox *mb,
                                uint64_t target_gpa, uint64_t shared_gpa,
                                uint64_t reps) {
    __atomic_store_n((uint64_t *)&mb->cfg_mode,       SYNC_CFG_MODE_TOGGLE, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_target_gpa, target_gpa,           __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_other_gpa,  0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_page_gpa,   0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_shared_gpa, shared_gpa,           __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_dec_line,   0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_flags,      0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_reserved0,  0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_host_lines, 0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_reps,       reps,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_aux0,       0ULL,                 __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_aux1,       0ULL,                 __ATOMIC_RELEASE);
    {
        uint64_t seq = __atomic_add_fetch((uint64_t *)&mb->cfg_ready_seq, 1ULL, __ATOMIC_SEQ_CST);
        while (__atomic_load_n((uint64_t *)&mb->cfg_ack_seq, __ATOMIC_ACQUIRE) < seq)
            __builtin_ia32_pause();
    }
}

/*
 * Scan readable mappings near AES_encrypt for Te0[0]=0xc66363a5 (OpenSSL
 * aes_core.c constant, read as little-endian uint32_t on x86).
 * Also verify Te0[1]=0xf87c7c84 to avoid false positives.
 */
static uint64_t find_te0_va(void) {
    /* OpenSSL aes_core.c: Te0[0]=0xc66363a5U, Te0[1]=0xf87c7c84U */
    static const uint32_t TE0_0 = 0xc66363a5u;
    static const uint32_t TE0_1 = 0xf87c7c84u;
    uintptr_t aes_fn = (uintptr_t)(void *)AES_encrypt;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[512];
    uintptr_t te0_va = 0;
    while (fgets(line, sizeof(line), maps) && !te0_va) {
        unsigned long start, end, file_off;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &file_off) < 4)
            continue;
        if (perms[0] != 'r') continue;
        /* Limit to mappings within 8MB of AES_encrypt */
        if (end < (aes_fn > 0x800000 ? aes_fn - 0x800000 : 0)) continue;
        if (start > aes_fn + 0x800000) continue;

        for (uintptr_t p = start; p + 8 <= end; p += 4) {
            if (*(volatile uint32_t *)p       == TE0_0 &&
                *(volatile uint32_t *)(p + 4) == TE0_1) {
                te0_va = p;
                break;
            }
        }
    }
    fclose(maps);
    return te0_va;
}

static uint64_t get_te0_gpa(uint64_t te0_file_offset) {
    (void)te0_file_offset;  /* unused: we scan for T0 directly */
    uintptr_t te0_va = find_te0_va();
    int fd = -1;
    struct snp_sync_va_to_gpa req;

    if (!te0_va) {
        fprintf(stderr, "[aes_toggle] T0 scan failed (AES_encrypt=0x%lx)\n",
                (unsigned long)(uintptr_t)(void *)AES_encrypt);
        return 0;
    }

    fd = open(SNP_SYNC_DEV, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[aes_toggle] open(%s) failed: %s\n", SNP_SYNC_DEV, strerror(errno));
        return 0;
    }
    memset(&req, 0, sizeof(req));
    req.va = (uint64_t)te0_va;
    if (ioctl(fd, SNP_SYNC_IOC_VA_TO_GPA, &req) != 0 || req.ret != 0) {
        fprintf(stderr, "[aes_toggle] VA_TO_GPA failed: %s ret=%d\n", strerror(errno), req.ret);
        close(fd);
        return 0;
    }
    close(fd);

    fprintf(stderr, "[aes_toggle] te0_va=0x%lx te0_gpa=0x%llx te0_page_gpa=0x%llx\n",
            (unsigned long)te0_va,
            (unsigned long long)req.gpa,
            (unsigned long long)(req.gpa & ~0xfffULL));
    return req.gpa;
}

int main(int argc, char **argv) {
    uint64_t te0_file_offset = DEFAULT_TE0_FILE_OFFSET;
    uint64_t iters = DEFAULT_ITERS;
    uint64_t te0_gpa = 0, target_gpa = 0, shared_gpa = 0;
    uint64_t guest_start_tsc = 0, guest_end_tsc = 0;
    uint64_t guest_total_calls = 0;
    struct timespec ts0 = {0}, ts1 = {0};
    int snp_fd = -1;
    volatile struct sync_mailbox *mb = NULL;
    AES_KEY aes_key;
    uint8_t pt[16], ct[16];
    uint32_t rng = 0x12345678u;

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--te0-file-offset") == 0)
            te0_file_offset = strtoull(argv[i+1], NULL, 0);
        else if (strcmp(argv[i], "--iters") == 0)
            iters = strtoull(argv[i+1], NULL, 0);
    }

    if (AES_set_encrypt_key(FIXED_KEY, 128, &aes_key) != 0) {
        fprintf(stderr, "[aes_toggle] AES_set_encrypt_key failed\n");
        return 1;
    }

    snp_fd = open(SNP_SYNC_DEV, O_RDWR);
    if (snp_fd < 0) {
        fprintf(stderr, "[aes_toggle] open(%s) failed: %s\n", SNP_SYNC_DEV, strerror(errno));
        return 1;
    }
    if (ioctl(snp_fd, SNP_SYNC_IOC_GET_GPA, &shared_gpa) != 0) {
        fprintf(stderr, "[aes_toggle] GET_GPA failed: %s\n", strerror(errno));
        close(snp_fd);
        return 1;
    }

    /* Enable debugcon output (port 0xe9) — required by wait_probe_shared_gpa */
    ioperm(DEBUGCON_PORT, 1, 1);
    void *m = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, snp_fd, 0);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[aes_toggle] mmap failed: %s\n", strerror(errno));
        close(snp_fd);
        return 1;
    }
    mb = (volatile struct sync_mailbox *)m;

    /* Zero mailbox fields */
    __atomic_store_n((uint64_t *)&mb->guest_seq,    0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->host_seq,     0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->phase_seq,    0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->phase_ack,    0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->phase_kind,   0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->phase_magic,  SYNC_MAILBOX_MAGIC, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_ready_seq,0ULL, __ATOMIC_RELEASE);
    __atomic_store_n((uint64_t *)&mb->cfg_ack_seq,  0ULL, __ATOMIC_RELEASE);
    __asm__ __volatile__("sfence" ::: "memory");

    te0_gpa = get_te0_gpa(te0_file_offset);
    if (te0_gpa == 0) {
        fprintf(stderr, "[aes_toggle] failed to get te0_gpa\n");
        return 1;
    }
    target_gpa = te0_gpa & ~(LINE_SZ - 1ULL);  /* cache-line aligned */

    /* Signal host preload: write SNP_PROBE line to debugcon.
     * wait_probe_shared_gpa() scans for "SNP_PROBE " + "shared_gpa=0x". */
    debugcon_printf("SNP_PROBE AES_TOGGLE target_gpa=0x%llx shared_gpa=0x%llx\n",
                    (unsigned long long)target_gpa, (unsigned long long)shared_gpa);

    fprintf(stderr, "[aes_toggle] target_gpa=0x%llx shared_gpa=0x%llx iters=%llu\n",
            (unsigned long long)target_gpa, (unsigned long long)shared_gpa,
            (unsigned long long)iters);
    fprintf(stderr, "[aes_toggle] Group A: pt[0] in {0..7} → T0[0..7] → target line\n");
    fprintf(stderr, "[aes_toggle] Group B: pt[0] in {128..255} → T0[128..255] → other page\n");
    fflush(stderr);

    /* Publish cfg to host */
    publish_cfg(mb, target_gpa, shared_gpa, iters * 2);

    /* Main toggle loop: A, B, A, B, ... */
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts0);
    guest_start_tsc = rdtscp64();
    for (uint64_t i = 0; i < iters; i++) {
        /* Simple LCG for random pt bytes 1..15 */
        rng = rng * 1664525u + 1013904223u;

        /* --- Group A --- */
        memset(pt, 0, 16);
        pt[0] = GROUP_A_BYTES[i & 7];
        for (int j = 1; j < 16; j++) { rng = rng * 1664525u + 1013904223u; pt[j] = (uint8_t)(rng >> 24); }
        AES_encrypt(pt, ct, &aes_key);
        guest_total_calls++;
        __asm__ __volatile__("" ::: "memory");
        /* Write group label BEFORE signaling (release ordering) */
        __atomic_store_n((uint64_t *)&mb->phase_kind, GROUP_A_LABEL, __ATOMIC_RELEASE);
        {
            uint64_t seq = signal_host(mb);
            wait_host_ack(mb, seq);
        }

        /* --- Group B --- */
        memset(pt, 0, 16);
        pt[0] = GROUP_B_BYTES[i & 7];
        for (int j = 1; j < 16; j++) { rng = rng * 1664525u + 1013904223u; pt[j] = (uint8_t)(rng >> 24); }
        AES_encrypt(pt, ct, &aes_key);
        guest_total_calls++;
        __asm__ __volatile__("" ::: "memory");
        __atomic_store_n((uint64_t *)&mb->phase_kind, GROUP_B_LABEL, __ATOMIC_RELEASE);
        {
            uint64_t seq = signal_host(mb);
            wait_host_ack(mb, seq);
        }
    }
    guest_end_tsc = rdtscp64();
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

    {
        uint64_t dt_tsc = guest_end_tsc > guest_start_tsc ? guest_end_tsc - guest_start_tsc : 0;
        uint64_t dt_ns = 0;
        if (ts1.tv_sec > ts0.tv_sec || (ts1.tv_sec == ts0.tv_sec && ts1.tv_nsec >= ts0.tv_nsec)) {
            dt_ns = (uint64_t)(ts1.tv_sec - ts0.tv_sec) * 1000000000ULL +
                    (uint64_t)(ts1.tv_nsec - ts0.tv_nsec);
        }
        fprintf(stderr,
                "[aes_toggle] done iters=%llu guest_total_aes_calls=%llu guest_loop_cycles=%llu guest_loop_ns=%llu cycles_per_call=%.2f ns_per_call=%.2f\n",
                (unsigned long long)iters,
                (unsigned long long)guest_total_calls,
                (unsigned long long)dt_tsc,
                (unsigned long long)dt_ns,
                guest_total_calls ? (double)dt_tsc / (double)guest_total_calls : 0.0,
                guest_total_calls ? (double)dt_ns / (double)guest_total_calls : 0.0);
    }
    fflush(stderr);

    /* Signal done via phase_done */
    __atomic_store_n((uint64_t *)&mb->phase_done, 1ULL, __ATOMIC_RELEASE);

    /* Keep alive */
    for (;;) {
        struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&ts, NULL);
    }
    (void)ct;
    return 0;
}
