#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define HOST_RUNNER_PRELOAD 1
#include "../host_runner_preload_shared.h"

/*
 * LLC Prime+Count (实验 4.4-A)
 *
 * 工作原理：
 *   Host 用自有内存填充与 victim cache line 冲突的 LLC eviction set
 *   (prime)，然后等待 guest 发出信号后重新访问同一 eviction set。
 *
 *   与传统 Prime+Probe 的不同点在于，这里不再用 rdtsc 测量 probe 延迟，
 *   而是用 probe 期间的慢访问计数，统计 eviction set 中有多少条发生 miss，
 *   作为 Prime+Count 信号。
 *
 * 环境变量：
 *   HR_OUTDIR    输出目录
 *   HR_SYNC_LOG  guest 的 debugcon 日志路径
 *   HR_CPU       prime 线程 CPU
 *   HR_REPS      H1/H0 各采样次数（默认 50000）
 *   HR_PC_WAYS   eviction set 路数（默认 16）
 *   HR_PC_LLC_SZ LLC 大小 bytes（per-CCD，默认 32 MiB）
 *   HR_PC_FORCED_ITERS host-only 正控迭代次数（默认 4000）
 */

/* AMD EPYC Milan/Genoa: 每个 CCD 的 L3 = 32 MiB, 16-way, 64B line → 32768 sets
 */
#define PC_LLC_SZ_DEFAULT (32UL * 1024 * 1024)
#define PC_LLC_HW_WAYS 16UL
#define PC_LLC_WAYS_DEFAULT 16
#define PC_EXTRA_WAYS 4

/* rdtsc threshold (cycles) separating L3 hit (~40-45) from DRAM miss (~200+).
 */
#define PC_RDTSC_SLOW_CYCLES_DEFAULT 100UL

static int g_pagemap_fd = -1;

static uint64_t pc_virt_to_phys(const void *va) {
  uint64_t entry;
  off_t off = (off_t)((uintptr_t)va / PAGE_SZ * 8);
  if (g_pagemap_fd < 0)
    g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
  if (g_pagemap_fd < 0)
    return 0;
  if (pread(g_pagemap_fd, &entry, 8, off) != 8)
    return 0;
  if (!(entry >> 63))
    return 0;
  {
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn << 12) | ((uintptr_t)va & (PAGE_SZ - 1));
  }
}

static volatile uint8_t **pc_build_evset(uint64_t victim_hpa, size_t llc_sz,
                                         int total_ways, void **base_out,
                                         size_t *sz_out, int *found_out) {
  const size_t cl_sz = 64;
  const size_t hw_ways = PC_LLC_HW_WAYS;
  size_t n_sets = llc_sz / (hw_ways * cl_sz);
  size_t n_sets_pg = PAGE_SZ / cl_sz;
  size_t pfn_period = n_sets / n_sets_pg;
  uint64_t victim_set = (victim_hpa >> 6) & (n_sets - 1);
  uint64_t wanted_pfn_mod = victim_set / n_sets_pg;
  size_t wanted_cl_off = (size_t)(victim_set % n_sets_pg) * cl_sz;
  size_t pool_pages = pfn_period * (size_t)total_ways * 4;
  size_t pool_sz = pool_pages * PAGE_SZ;
  uint8_t *pool;
  volatile uint8_t **evset;
  int count = 0;

  if (pool_sz > 256UL * 1024 * 1024) {
    fprintf(stderr,
            "[HR/pc] build_evset: pool_sz=%zu MB exceeds 256 MB limit\n",
            pool_sz / (1024 * 1024));
    return NULL;
  }

  pool = mmap(NULL, pool_sz, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (pool == MAP_FAILED)
    return NULL;

  evset = malloc((size_t)total_ways * sizeof(volatile uint8_t *));
  if (!evset) {
    munmap(pool, pool_sz);
    return NULL;
  }

  for (size_t pg = 0; pg < pool_pages && count < total_ways; pg++) {
    uint8_t *va = pool + pg * PAGE_SZ;
    uint64_t pa = pc_virt_to_phys(va);
    uint64_t pfn;
    if (!pa)
      continue;
    pfn = pa >> 12;
    if ((pfn % pfn_period) == wanted_pfn_mod)
      evset[count++] = (volatile uint8_t *)(va + wanted_cl_off);
  }

  if (count < total_ways) {
    fprintf(stderr,
            "[HR/pc] build_evset: 仅找到 %d/%d 同 set 页（victim_hpa=0x%llx "
            "set=%llu）\n",
            count, total_ways, (unsigned long long)victim_hpa,
            (unsigned long long)victim_set);
    if (count < 4) {
      free(evset);
      munmap(pool, pool_sz);
      return NULL;
    }
  }

  for (int i = 0; i < count; i++)
    (void)*evset[i];
  _mm_mfence();

  *base_out = pool;
  *sz_out = pool_sz;
  if (found_out)
    *found_out = count;
  return evset;
}

static void pc_prime(volatile uint8_t **ev, int n) {
  for (int i = n - 1; i >= 0; i--)
    (void)*ev[i];
  _mm_mfence();
}

struct pc_probe_diag {
  uint64_t miss_cnt;
  int probe_n;
};

static struct pc_probe_diag pc_probe_collect(volatile uint8_t **ev, int n,
                                             uint64_t slow_cycles) {
  struct pc_probe_diag d = {.miss_cnt = 0, .probe_n = 0};
  uint32_t lo, hi;
  uint64_t t0, t1;

  d.probe_n = n > (int)PC_LLC_HW_WAYS ? (int)PC_LLC_HW_WAYS : n;
  if (d.probe_n <= 0)
    return d;

  _mm_mfence();
  for (int i = 0; i < d.probe_n; i++) {
    __asm__ volatile("lfence\nrdtsc" : "=a"(lo), "=d"(hi)::"memory");
    t0 = ((uint64_t)hi << 32) | lo;
    (void)*ev[i];
    __asm__ volatile("lfence\nrdtsc" : "=a"(lo), "=d"(hi)::"memory");
    t1 = ((uint64_t)hi << 32) | lo;
    if (t1 - t0 > slow_cycles)
      d.miss_cnt++;
  }
  return d;
}

static void pc_flush(volatile uint8_t **ev, int n) {
  for (int i = 0; i < n; i++)
    _mm_clflush((void *)ev[i]);
  _mm_mfence();
}

struct pc_forced_ctrl_diag {
  int iters;
  double base_avg_miss;
  double off_avg_miss;
  double on_avg_miss;
  double on_minus_off;
  double on_over_off;
  double on_gt_off_ratio;
};

static struct pc_forced_ctrl_diag
pc_run_forced_ctrl(struct hr_reader_ctx *target_reader, int target_line,
                   struct hr_reader_ctx *other_reader, int other_line,
                   volatile uint8_t **ev, int nways, int iters, int prime_cpu,
                   int probe_cpu, uint64_t slow_cycles) {
  struct pc_forced_ctrl_diag out = {0};
  uint64_t sum_base = 0, sum_off = 0, sum_on = 0;
  int cnt_on_gt_off = 0;

  if (!ev || nways <= 0 || iters <= 0)
    return out;

  for (int i = 0; i < iters; i++) {
    struct pc_probe_diag d_base, d_off, d_on;
    uint64_t probe_cycles = 0;

    maybe_pin_cpu(prime_cpu);
    pc_flush(ev, nways);
    pc_prime(ev, nways);
    maybe_pin_cpu(probe_cpu);
    d_base = pc_probe_collect(ev, nways, slow_cycles);

    maybe_pin_cpu(prime_cpu);
    pc_flush(ev, nways);
    pc_prime(ev, nways);
    maybe_pin_cpu(probe_cpu);
    (void)hr_reader_measure_line(other_reader, other_line, &probe_cycles);
    d_off = pc_probe_collect(ev, nways, slow_cycles);

    maybe_pin_cpu(prime_cpu);
    pc_flush(ev, nways);
    pc_prime(ev, nways);
    maybe_pin_cpu(probe_cpu);
    (void)hr_reader_measure_line(target_reader, target_line, &probe_cycles);
    d_on = pc_probe_collect(ev, nways, slow_cycles);

    sum_base += d_base.miss_cnt;
    sum_off += d_off.miss_cnt;
    sum_on += d_on.miss_cnt;
    if (d_on.miss_cnt > d_off.miss_cnt)
      cnt_on_gt_off++;
  }

  out.iters = iters;
  out.base_avg_miss = (double)sum_base / (double)iters;
  out.off_avg_miss = (double)sum_off / (double)iters;
  out.on_avg_miss = (double)sum_on / (double)iters;
  out.on_minus_off = out.on_avg_miss - out.off_avg_miss;
  out.on_over_off =
      (out.off_avg_miss > 0.0) ? (out.on_avg_miss / out.off_avg_miss) : 0.0;
  out.on_gt_off_ratio = (double)cnt_on_gt_off / (double)iters;
  return out;
}

void *hr_mode_pc_impl(void *arg) {
  const char *outdir = getenv("HR_OUTDIR");
  const char *sync_log = getenv("HR_SYNC_LOG");
  const char *env;
  int reps = 50000;
  int prime_cpu = -1;
  int probe_cpu = -1;
  int ways = PC_LLC_WAYS_DEFAULT;
  int forced_iters = 4000;
  size_t llc_sz = PC_LLC_SZ_DEFAULT;
  uint64_t slow_cycles = PC_RDTSC_SLOW_CYCLES_DEFAULT;
  uint64_t target_gpa = 0, other_gpa = 0, shared_gpa = 0;
  uint64_t log_off = 0;
  uint64_t last_cfg_seq = 0;
  uint64_t last_guest_seq = 0;
  int vm_fd = -1;
  int shared_fd = -1;
  volatile uint64_t *shared_ptr = NULL;
  volatile struct sync_mailbox *sync_mb = NULL;
  struct sync_cfg_snapshot cfg;
  FILE *fh1 = NULL, *fh0 = NULL, *meta = NULL;
  void *alloc_base = NULL;
  size_t alloc_sz = 0;
  volatile uint8_t **evset = NULL;
  int nways_total, nways_on = 0;
  int collected_h1 = 0, collected_h0 = 0;
  uint64_t h1_sum_miss = 0, h0_sum_miss = 0;
  int probe_n = 0;
  struct pc_forced_ctrl_diag forced_diag = {0};
  uint64_t target_page_gpa, other_page_gpa;
  int target_line, other_line;
  uint64_t seq = 0;
  struct hr_reader_ctx target_reader = {.fd = -1};
  struct hr_reader_ctx other_reader = {.fd = -1};

  (void)arg;
  if (!outdir || !sync_log)
    return NULL;
  if ((env = getenv("HR_REPS")))
    reps = atoi(env);
  if ((env = getenv("HR_CPU")))
    prime_cpu = atoi(env);
  if ((env = getenv("HR_PROBE_CPU")))
    probe_cpu = atoi(env);
  if ((env = getenv("HR_PC_WAYS")))
    ways = atoi(env);
  if ((env = getenv("HR_PC_LLC_SZ")))
    llc_sz = (size_t)strtoull(env, NULL, 0);
  if ((env = getenv("HR_PC_FORCED_ITERS")))
    forced_iters = atoi(env);
  if ((env = getenv("HR_PC_SLOW_CYCLES")))
    slow_cycles = strtoull(env, NULL, 0);

  if (prime_cpu >= 0 && probe_cpu < 0)
    probe_cpu = prime_cpu + 1;

  nways_total = ways + PC_EXTRA_WAYS;

  wait_file_exists(sync_log);
  if (wait_probe_shared_gpa(sync_log, &log_off, &shared_gpa) != 0)
    return NULL;

  maybe_pin_cpu(prime_cpu);

  for (int i = 0; i < 50; i++) {
    vm_fd = find_self_kvm_vm_fd();
    if (vm_fd >= 0)
      break;
    usleep(100000);
  }
  if (vm_fd < 0) {
    fprintf(stderr, "[HR/pc] vm_fd not found\n");
    return NULL;
  }
  if (hr_reader_open(&target_reader) != 0 ||
      hr_reader_open(&other_reader) != 0) {
    fprintf(stderr, "[HR/pc] open %s failed: errno=%d (%s)\n",
            HPA_READER_DEV, errno, strerror(errno));
    if (vm_fd >= 0)
      close(vm_fd);
    return NULL;
  }

  shared_ptr = map_shared_counter_page(vm_fd, shared_gpa, &shared_fd, NULL);
  if (!shared_ptr) {
    fprintf(stderr, "[HR/pc] map_shared_counter_page failed\n");
    return NULL;
  }
  sync_mb = (volatile struct sync_mailbox *)shared_ptr;
  if (wait_mailbox_magic(sync_mb, 10.0) != 0) {
    fprintf(stderr, "[HR/pc] mailbox magic timeout\n");
    goto done;
  }
  last_guest_seq =
      __atomic_load_n((const uint64_t *)&sync_mb->guest_seq, __ATOMIC_ACQUIRE);
  if (wait_guest_cfg(sync_mb, last_cfg_seq, 30.0, &cfg) != 0) {
    fprintf(stderr, "[HR/pc] wait_guest_cfg timeout\n");
    goto done;
  }
  last_cfg_seq = cfg.seq;
  if (cfg.mode != SYNC_CFG_MODE_PC) {
    fprintf(stderr, "[HR/pc] unexpected cfg_mode=%llu\n",
            (unsigned long long)cfg.mode);
    goto done;
  }
  target_gpa = cfg.target_gpa;
  other_gpa = cfg.other_gpa;

  maybe_pin_cpu(prime_cpu);

  {
    uint64_t victim_hpa = 0;
    uint64_t victim_hpa_page = 0;
    uint64_t target_line_off = target_gpa & (PAGE_SZ - 1ULL);

    target_page_gpa = target_gpa & ~(PAGE_SZ - 1ULL);
    other_page_gpa = other_gpa & ~(PAGE_SZ - 1ULL);
    target_line = (int)((target_gpa & (PAGE_SZ - 1ULL)) / LINE_SZ);
    other_line = (int)((other_gpa & (PAGE_SZ - 1ULL)) / LINE_SZ);
    if (hr_reader_bind(&target_reader, vm_fd, target_page_gpa,
                       HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0 ||
        hr_reader_bind(&other_reader, vm_fd, other_page_gpa,
                       HPA_READER_MODE_CIPHERTEXT_CACHEABLE) != 0) {
      fprintf(stderr,
              "[HR/pc] hr_reader_bind failed: target_page_gpa=0x%llx other_page_gpa=0x%llx errno=%d (%s)\n",
              (unsigned long long)target_page_gpa,
              (unsigned long long)other_page_gpa,
              errno, strerror(errno));
      goto done;
    }

    if (translate_gpa_to_hpa(vm_fd, target_gpa, &victim_hpa_page) != 0) {
      fprintf(stderr,
              "[HR/pc] GPA→HPA 翻译失败 (gpa=0x%llx)，回退至 victim_hpa=0\n",
              (unsigned long long)target_gpa);
      victim_hpa = 0;
    } else {
      victim_hpa = victim_hpa_page + target_line_off;
      fprintf(stderr,
              "[HR/pc] target GPA=0x%llx → HPA=0x%llx (page=0x%llx off=0x%llx) "
              "set_idx=%llu\n",
              (unsigned long long)target_gpa, (unsigned long long)victim_hpa,
              (unsigned long long)victim_hpa_page,
              (unsigned long long)target_line_off,
              (unsigned long long)((victim_hpa >> 6) &
                                   (llc_sz / (PC_LLC_HW_WAYS * 64) - 1)));
    }

    evset = pc_build_evset(victim_hpa, llc_sz, nways_total, &alloc_base,
                           &alloc_sz, &nways_on);
    if (!evset) {
      fprintf(stderr, "[HR/pc] build_evset failed\n");
      goto done;
    }
    if (nways_on < 4) {
      fprintf(stderr, "[HR/pc] build_evset on-set too small: %d\n", nways_on);
      goto done;
    }

    maybe_pin_cpu(probe_cpu);
    forced_diag = pc_run_forced_ctrl(
        &target_reader, target_line, &other_reader, other_line, evset,
        nways_on, forced_iters, prime_cpu, probe_cpu, slow_cycles);
    fprintf(stderr,
            "[HR/pc] forced_ctrl: iters=%d base=%.2f off=%.2f on=%.2f "
            "delta(on-off)=%.2f ratio(on/off)=%.3f gt=%.3f\n",
            forced_diag.iters, forced_diag.base_avg_miss,
            forced_diag.off_avg_miss, forced_diag.on_avg_miss,
            forced_diag.on_minus_off, forced_diag.on_over_off,
            forced_diag.on_gt_off_ratio);

    if (ensure_dir_p(outdir) != 0)
      goto done;

    {
      char h1p[512], h0p[512];
      snprintf(h1p, sizeof(h1p), "%s/raw_h1_counts.csv", outdir);
      snprintf(h0p, sizeof(h0p), "%s/raw_h0_counts.csv", outdir);
      fh1 = fopen(h1p, "w");
      fh0 = fopen(h0p, "w");
      if (!fh1 || !fh0)
        goto done;
      fprintf(fh1, "count\n");
      fprintf(fh0, "count\n");
    }

    if (wait_sync_guest_seq(sync_mb, last_guest_seq, 2.0, &seq) != 0)
      goto done;
    signal_sync_host_ack(sync_mb, seq);
    last_guest_seq = seq;
    for (int i = 0; i < 200; i++) {
      struct pc_probe_diag d;
      uint64_t warm_seq = 0;
      maybe_pin_cpu(prime_cpu);
      pc_flush(evset, nways_on);
      pc_prime(evset, nways_on);
      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 2.0, &warm_seq) != 0)
        break;
      signal_sync_host_ack(sync_mb, warm_seq);
      last_guest_seq = warm_seq;
      maybe_pin_cpu(probe_cpu);
      d = pc_probe_collect(evset, nways_on, slow_cycles);
      if (probe_n == 0)
        probe_n = d.probe_n;
      seq = warm_seq;
    }

    while (collected_h1 < reps || collected_h0 < reps) {
      struct pc_probe_diag d;
      uint64_t next_seq = 0;

      maybe_pin_cpu(prime_cpu);
      pc_flush(evset, nways_on);
      pc_prime(evset, nways_on);
      if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &next_seq) != 0)
        break;
      signal_sync_host_ack(sync_mb, next_seq);
      last_guest_seq = next_seq;
      maybe_pin_cpu(probe_cpu);
      d = pc_probe_collect(evset, nways_on, slow_cycles);
      if (probe_n == 0)
        probe_n = d.probe_n;

      if ((next_seq & 1ULL) != 0) {
        if (collected_h1 >= reps)
          continue;
        if (fh1)
          fprintf(fh1, "%llu\n", (unsigned long long)d.miss_cnt);
        h1_sum_miss += d.miss_cnt;
        collected_h1++;
      } else {
        if (collected_h0 >= reps)
          continue;
        if (fh0)
          fprintf(fh0, "%llu\n", (unsigned long long)d.miss_cnt);
        h0_sum_miss += d.miss_cnt;
        collected_h0++;
      }
    }

    if (fh1)
      fflush(fh1);
    if (fh0)
      fflush(fh0);

    {
      char meta_path[512], done_path[512];
      FILE *df;
      double h0_avg_miss =
          collected_h0 ? (double)h0_sum_miss / collected_h0 : 0.0;
      double h1_avg_miss =
          collected_h1 ? (double)h1_sum_miss / collected_h1 : 0.0;
      snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", outdir);
      meta = fopen(meta_path, "w");
      if (meta) {
        fprintf(
            meta,
            "mode=prime+count\nllc_sz=%zu\nways=%d\n"
            "target_gpa=0x%llx\n"
            "other_gpa=0x%llx\n"
            "target_line_off=0x%llx\n"
            "target_hpa=0x%llx\n"
            "evset_count=%d\n"
            "probe_n=%d\n"
            "slow_cycles_threshold=%llu\n"
            "forced_ctrl_iters=%d\n"
            "forced_ctrl_base_avg_miss=%.6f\n"
            "forced_ctrl_off_avg_miss=%.6f\n"
            "forced_ctrl_on_avg_miss=%.6f\n"
            "forced_ctrl_on_minus_off=%.6f\n"
            "forced_ctrl_on_over_off=%.6f\n"
            "forced_ctrl_on_gt_off_ratio=%.6f\n"
            "h0_avg_probe_miss_count=%.6f\n"
            "h1_avg_probe_miss_count=%.6f\n"
            "collected_h1=%d\ncollected_h0=%d\nprime_cpu=%d\nprobe_cpu=%d\n",
            llc_sz, ways, (unsigned long long)target_gpa,
            (unsigned long long)other_gpa, (unsigned long long)target_line_off,
            (unsigned long long)victim_hpa, nways_on, probe_n,
            (unsigned long long)slow_cycles, forced_diag.iters,
            forced_diag.base_avg_miss, forced_diag.off_avg_miss,
            forced_diag.on_avg_miss, forced_diag.on_minus_off,
            forced_diag.on_over_off, forced_diag.on_gt_off_ratio, h0_avg_miss,
            h1_avg_miss, collected_h1, collected_h0, prime_cpu, probe_cpu);
        fclose(meta);
        meta = NULL;
      }
      snprintf(done_path, sizeof(done_path), "%s/pc_done.txt", outdir);
      df = fopen(done_path, "w");
      if (df) {
        fprintf(df, "h1=%d h0=%d\n", collected_h1, collected_h0);
        fclose(df);
      }
    }
    fprintf(stderr,
            "[HR/pc] done: H1=%d H0=%d probe_n=%d avg_miss(H0/H1)=%.3f/%.3f\n",
            collected_h1, collected_h0, probe_n,
            collected_h0 ? (double)h0_sum_miss / collected_h0 : 0.0,
            collected_h1 ? (double)h1_sum_miss / collected_h1 : 0.0);
  }

done:
  hr_reader_close(&target_reader);
  hr_reader_close(&other_reader);
  if (fh1)
    fclose(fh1);
  if (fh0)
    fclose(fh0);
  free(evset);
  if (alloc_base && alloc_sz)
    munmap(alloc_base, alloc_sz);
  if (shared_ptr && shared_fd >= 0)
    munmap((void *)shared_ptr, PAGE_SZ);
  if (shared_fd >= 0)
    close(shared_fd);
  if (vm_fd >= 0)
    close(vm_fd);
  return NULL;
}

void *hr_main_thread_pc(void *arg) { return hr_mode_pc_impl(arg); }
