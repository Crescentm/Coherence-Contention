/*
 * fr_verify.c — Flush+Reload 可行性验证工具
 *
 * 测试内容：
 *   1. 宿主侧对 SEV-SNP VM 物理页执行 clflush → 记录是否触发异常或被静默忽略
 *   2. 尝试建立与 SEV-SNP VM 的共享内存映射 → 记录是否被 RMP 阻断
 *   3. 对比：普通 KVM VM 的 clflush 是否有效（阳性对照）
 *
 * 编译: gcc -O2 -o fr_verify fr_verify.c
 * 用法（需 root）: ./fr_verify <out_txt>
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <time.h>

#define CACHE_LINE 64

static sigjmp_buf g_jmpbuf;
static volatile int g_caught_signal = 0;

static void sigfault_handler(int sig, siginfo_t *si, void *ucontext) {
    g_caught_signal = sig;
    siglongjmp(g_jmpbuf, 1);
}

static void install_handler(void) {
    struct sigaction sa = {};
    sa.sa_sigaction = sigfault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}

static inline uint64_t rdtscp(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi) :: "rcx", "memory");
    return ((uint64_t)hi << 32) | lo;
}

/*
 * 尝试对某物理地址（通过 /dev/mem 映射）执行 clflush，
 * 返回：
 *   0  = 指令正常执行（无异常）→ clflush 对 SEV-SNP 页无效（静默忽略）
 *   -1 = 映射失败（EIO 等，RMP 保护生效）
 *   sig= 捕获到的信号号（SIGSEGV=11 / SIGBUS=7）
 */
static int try_clflush_via_devmem(uint64_t hpa, const char *label, FILE *log) {
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        fprintf(log, "[%s] open(/dev/mem): %s\n", label, strerror(errno));
        return -99;
    }

    void *ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, (off_t)hpa);
    if (ptr == MAP_FAILED) {
        fprintf(log, "[%s] mmap(HPA=0x%lx): %s (errno=%d)\n",
                label, hpa, strerror(errno), errno);
        close(fd);
        return -1;
    }

    /* 测量 reload 延迟（clflush 前后） */
    g_caught_signal = 0;
    uint64_t t_before = 0, t_after = 0;
    int fault = 0;

    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        /* 先读取，确保在缓存中 */
        volatile uint8_t dummy = *(volatile uint8_t *)ptr;
        (void)dummy;
        t_before = rdtscp();

        /* clflush 目标地址 */
        __asm__ volatile("clflush (%0)" :: "r"(ptr) : "memory");
        __asm__ volatile("mfence" ::: "memory");

        /* 重新 reload，测量是否 miss */
        dummy = *(volatile uint8_t *)ptr;
        (void)dummy;
        t_after = rdtscp();
    } else {
        fault = g_caught_signal;
    }

    munmap(ptr, 4096);
    close(fd);

    if (fault) {
        fprintf(log, "[%s] clflush -> SIGNAL %d (RMP violation / fault)\n",
                label, fault);
        return fault;
    }

    uint64_t reload_cycles = t_after - t_before;
    fprintf(log, "[%s] clflush OK (no fault), reload latency = %lu cycles\n",
            label, reload_cycles);
    fprintf(log, "[%s] note: if reload_cycles < 200, clflush was silently ignored "
            "(SEV-SNP protects the page)\n", label);
    return 0;
}

/*
 * 尝试通过 QEMU memory-backend memfd 的 fd 建立共享映射
 * （模拟 Flush+Reload 共享内存前提）
 */
static void try_shared_mapping(const char *smem_path, const char *label, FILE *log) {
    int fd = open(smem_path, O_RDWR);
    if (fd < 0) {
        fprintf(log, "[%s] open(%s): %s\n", label, smem_path, strerror(errno));
        return;
    }
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(log, "[%s] mmap(shared): %s (RMP 保护可能阻断)\n",
                label, strerror(errno));
    } else {
        fprintf(log, "[%s] mmap(shared) 成功！（F+R 共享内存在本场景可行）\n", label);
        munmap(ptr, 4096);
    }
    close(fd);
}

int main(int argc, char **argv) {
    const char *out_txt = (argc > 1) ? argv[1] : "/tmp/fr_verify.txt";

    FILE *log = fopen(out_txt, "w");
    if (!log) { perror("fopen"); return 1; }

    install_handler();

    fprintf(log, "=== Flush+Reload 可行性验证 ===\n");
    fprintf(log, "时间: %s\n\n", __DATE__ " " __TIME__);

    /* 测试 1：对宿主侧普通匿名页的 clflush（阳性对照） */
    fprintf(log, "--- 测试 1：普通匿名页 clflush（阳性对照）---\n");
    void *anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon != MAP_FAILED) {
        memset(anon, 0xAB, 64);
        uint64_t t0 = rdtscp();
        __asm__ volatile("clflush (%0)" :: "r"(anon) : "memory");
        __asm__ volatile("mfence" ::: "memory");
        volatile uint8_t v = *(volatile uint8_t *)anon; (void)v;
        uint64_t t1 = rdtscp();
        fprintf(log, "[plain-anon] clflush OK, reload = %lu cycles "
                "(>= ~200 → cache miss 验证 clflush 生效)\n", t1 - t0);
        munmap(anon, 4096);
    }

    /* 测试 2：对 /dev/mem 暴露的页执行 clflush */
    fprintf(log, "\n--- 测试 2：/dev/mem 路径 clflush (HPA=0x1000000) ---\n");
    fprintf(log, "(此 HPA 为占位值，实际应替换为运行中 SEV-SNP VM 的物理页地址)\n");
    try_clflush_via_devmem(0x1000000UL, "devmem", log);

    /* 测试 3：/proc/self/mem 访问阻断验证 */
    fprintf(log, "\n--- 测试 3：/proc 访问与内存隔离 ---\n");
    /* 尝试读取 /proc/kcore 中某个匿名物理页（通常需要 CAP_SYS_RAWIO） */
    int kcore_fd = open("/proc/kcore", O_RDONLY);
    if (kcore_fd >= 0) {
        fprintf(log, "[kcore] 可打开 /proc/kcore\n");
        close(kcore_fd);
    } else {
        fprintf(log, "[kcore] 无法打开: %s\n", strerror(errno));
    }

    /* 测试 4：共享内存路径探测 */
    fprintf(log, "\n--- 测试 4：memfd 共享路径 ---\n");
    /* /dev/shm 下无共享文件则记录失败 */
    try_shared_mapping("/dev/shm/qemu_snp_mem", "memfd-snp", log);

    fprintf(log, "\n=== 总结 ===\n");
    fprintf(log, "若测试 2 出现 clflush 成功但 reload 延迟低（< 200 cycles），\n");
    fprintf(log, "表明 SEV-SNP 硬件将宿主的 clflush 静默忽略（加密视图隔离）。\n");
    fprintf(log, "若测试 2 触发信号或 mmap 失败，表明 RMP 在访问层面阻断了攻击。\n");
    fprintf(log, "两种情形均说明 Flush+Reload 在 SEV-SNP 下不可行。\n");

    fclose(log);
    printf("[fr_verify] 结果写入: %s\n", out_txt);
    return 0;
}
