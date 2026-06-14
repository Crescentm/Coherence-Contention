#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

// 获取虚拟地址对应的物理地址（利用 pagemap）
uint64_t get_physical_address(void *vaddr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        exit(1);
    }
    uint64_t offset = ((uint64_t)vaddr / getpagesize()) * 8;
    uint64_t pme;
    if (pread(fd, &pme, 8, offset) != 8) {
        perror("read pagemap");
        exit(1);
    }
    close(fd);
    if ((pme & (1ULL << 63)) == 0) {
        fprintf(stderr, "Page not present\n");
        exit(1);
    }
    uint64_t pfn = pme & ((1ULL << 55) - 1);
    return pfn * getpagesize() + ((uint64_t)vaddr % getpagesize());
}

static inline void clflush(volatile void *p) {
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

static inline void mfence() {
    asm volatile("mfence" ::: "memory");
}

static inline uint64_t rdtscp() {
    unsigned int aux;
    return __builtin_ia32_rdtscp(&aux);
}

int main(int argc, char **argv) {
    int cbit_pos = 51; // 默认使用 Milan 的 C-bit 位置
    int reps = 10000;

    if (argc > 1) cbit_pos = atoi(argv[1]);
    if (argc > 2) reps = atoi(argv[2]);

    printf("=== 实验 4.1-C: Host-only C-bit 跨域一致性逐出验证 (kmod 版本) ===\n");
    printf("C-bit 位置: %d\n", cbit_pos);
    printf("采样次数: %d\n", reps);

    // 1. 在用户态分配一页普通内存，并强制锁定物理内存
    void *base = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap anon");
        exit(1);
    }
    memset(base, 0x42, 4096);

    // 2. 解析它的系统物理地址 (HPA)
    uint64_t hpa = get_physical_address(base);
    printf("分配得到的基准 HPA: 0x%lx\n", hpa);

    // 3. 通过自定义模块建立物理页映射绕过 STRICT_DEVMEM
    int fd_mem = open("/dev/cbit_mmap", O_RDWR);
    if (fd_mem < 0) {
        perror("无法打开 /dev/cbit_mmap。请确保运行了 sudo insmod dev_cbit.ko");
        exit(1);
    }

    uint64_t pfn_normal = hpa;
    uint64_t cbit_mask = (1ULL << cbit_pos);
    uint64_t pfn_cbit = hpa | cbit_mask;

    // 因为驱动里用的是 pgoff 作为 pfn
    void *ptr_nocbit = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, (off_t)pfn_normal);
    void *ptr_cbit   = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, (off_t)pfn_cbit);

    if (ptr_nocbit == MAP_FAILED || ptr_cbit == MAP_FAILED) {
        perror("mmap /dev/cbit_mmap 失败");
        exit(1);
    }

    printf("映射 1 (无 C-bit，探测者视图) : %p (PFN: 0x%lx)\n", ptr_nocbit, pfn_normal);
    printf("映射 2 (有 C-bit，填充者视图) : %p (PFN: 0x%lx)\n", ptr_cbit, pfn_cbit);

    FILE *f_h0 = fopen("host_only_h0.csv", "w");
    FILE *f_h1 = fopen("host_only_h1.csv", "w");
    fprintf(f_h0, "cycles\n");
    fprintf(f_h1, "cycles\n");

    volatile uint8_t *p_nc = (volatile uint8_t *)ptr_nocbit;
    volatile uint8_t *p_c  = (volatile uint8_t *)ptr_cbit;

    for(int i=0; i<1000; i++) {
        clflush(p_nc);
        mfence();
        volatile uint8_t d = *p_nc;
        (void)d;
    }

    printf("\n正在采集 H0 (基准 DRAM / 无 C-bit 逐出) 样本...\n");
    for(int i=0; i<reps; i++) {
        clflush(p_nc);
        clflush(p_c);
        mfence();

        uint64_t t1 = rdtscp();
        volatile uint8_t val = *p_nc;
        uint64_t t2 = rdtscp();
        (void)val;

        fprintf(f_h0, "%lu\n", t2 - t1);

        for(volatile int j=0; j<200; j++);
    }

    printf("正在采集 H1 (Host-only 下依然存在 C-bit 逐出) 样本...\n");
    for(int i=0; i<reps; i++) {
        clflush(p_nc);
        clflush(p_c);
        mfence();

        *p_c = 0x55;
        mfence();

        uint64_t t1 = rdtscp();
        volatile uint8_t val = *p_nc;
        uint64_t t2 = rdtscp();
        (void)val;

        fprintf(f_h1, "%lu\n", t2 - t1);

        for(volatile int j=0; j<200; j++);
    }

    fclose(f_h0);
    fclose(f_h1);

    printf("测试完成，输出保存至 host_only_h0.csv 和 host_only_h1.csv\n");
    return 0;
}
