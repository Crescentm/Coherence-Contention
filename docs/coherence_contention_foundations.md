# Cohere 实验基础：Coherence 与 Contention 实现说明

本文档总结当前代码中两类信号的实现基础：

- `Coherence`（跨域一致性驱逐/失配信号）
- `Contention`（纯 DRAM 竞争信号）

并附关键代码片段，便于论文写作与后续复现实验。

## 1. 共享页与同步协议基础

两个机制都依赖 guest 与 host 的共享 mailbox（`/dev/snp_sync` 对应页）：

- guest 用 `guest_seq` 发信号
- host 用 `host_seq` 回 ACK
- `cfg_*` 字段用于模式参数一次性发布

代码位置：
- `src/host_runner_preload_shared.h`

关键结构（节选）：

```c
struct sync_mailbox {
  volatile uint64_t guest_seq;
  volatile uint64_t host_seq;
  volatile uint64_t phase_seq;
  volatile uint64_t phase_ack;
  ...
  volatile uint64_t cfg_ready_seq;
  volatile uint64_t cfg_ack_seq;
  volatile uint64_t cfg_mode;
  volatile uint64_t cfg_target_gpa;
  volatile uint64_t cfg_other_gpa;
  volatile uint64_t cfg_shared_gpa;
  ...
};
```

## 2. Coherence 如何实现

### 2.1 Guest 侧：访问目标线后发同步信号

`sync` 模式中，guest 持续访问 `target`，随后通过共享页通知 host。

代码位置：
- `src/guest_probe.c`

关键片段：

```c
static inline uint64_t signal_host(volatile struct sync_mailbox *mb) {
  return __atomic_add_fetch((uint64_t *)&mb->guest_seq, 1ULL, __ATOMIC_SEQ_CST);
}

static inline void wait_host_ack(volatile struct sync_mailbox *mb, uint64_t seq) {
  while (__atomic_load_n((uint64_t *)&mb->host_seq, __ATOMIC_ACQUIRE) < seq) {
    __builtin_ia32_pause();
  }
}

static inline void guest_sync_round(volatile struct sync_mailbox *mb, volatile uint8_t *addr) {
  (void)*addr;
  uint64_t seq = signal_host(mb);
  wait_host_ack(mb, seq);
}
```

模式发布与主循环（节选）：

```c
publish_cfg(shared_mem, SYNC_CFG_MODE_SYNC, target_gpa, other_page_gpa, gpa,
            shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL);
for (;;) {
  guest_sync_round(shared_mem, target);
}
```

### 2.2 Host 侧：收到同步后立即测量目标页 cache line 延迟

host 在每个 `guest_seq` 到来后执行 `measure_line_ex()`，再 ACK 给 guest。

代码位置：
- `src/host_runner_modes/mode_single.c`
- `src/host_runner_modes/common_runtime.c`

关键片段：

```c
if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
  break;
cycles = measure_line_ex(vm_fd, target_gpa, line, probe_mode);
signal_sync_host_ack(sync_mb, seq);
last_guest_seq = seq;
```

测量函数（节选）：

```c
uint64_t measure_line_ex(int vm_fd, uint64_t page_gpa, int line, uint32_t mode) {
  struct kvm_amd_read_gpa p;
  p.gpa = page_gpa + (uint64_t)line * LINE_SZ;
  p.mode = mode; // cacheable 或 nocache
  ...
  return p.tsc_delta;
}
```

### 2.3 物理含义

Coherence 模式核心是：guest 对目标线访问后，host 在极短时间窗口里读取该线的密文视图，观测一致性协议造成的时延抬升（H1）相对基线（H0）的差异。

## 3. Contention 如何实现

### 3.1 Guest 侧：主动制造 DRAM 冲突窗口

`contention` 模式中，guest 每轮：

1. `clflush(target)`：将目标线从缓存驱逐
2. `load(target)`：强制触发 DRAM 访问并激活对应行
3. `signal_host + wait_ack`：让 host 在窗口内测量

代码位置：
- `src/guest_probe.c`

关键片段（节选）：

```c
_mm_clflush((void *)target);
_mm_mfence();
(void)*target;  // DRAM load
{
  uint64_t seq = signal_host(shared_mem);
  wait_host_ack(shared_mem, seq);
}
sleep_us(contention_pause_us);
```

对应配置发布：

```c
publish_cfg(shared_mem, SYNC_CFG_MODE_CONTENTION, target_gpa, other_page_gpa,
            gpa, shared_gpa, (uint64_t)dec_line, 0ULL, 0ULL, 0ULL,
            contention_pause_us, 0ULL);
```

### 3.2 Host 侧：NOCACHE 下采集 H0/H1

host 使用 `NOCACHE` 模式读两条路径：

- H0：`other_gpa`（非竞争）
- H1：`page_gpa`（竞争路径）

代码位置：
- `src/host_runner_modes/mode_contention.c`

关键片段：

```c
uint64_t c_h0 = measure_line_ex(vm_fd, other_gpa, 0,
                                KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE);
if (wait_sync_guest_seq(sync_mb, last_guest_seq, 10.0, &seq) != 0)
  break;
signal_sync_host_ack(sync_mb, seq);
c_h1 = measure_line_ex(vm_fd, page_gpa, 0,
                       KVM_AMD_READ_GPA_MODE_CIPHERTEXT_NOCACHE);
```

### 3.3 物理含义

Contention 模式刻意绕开缓存命中路径，突出 DRAM 子系统竞争（银行/行缓冲/控制器排队）带来的时延差。此时 H1-H0 主要代表“内存竞争”而不是一致性驱逐本身。

## 4. GPA -> HPA 翻译流程（结合当前 patch）

你当前实现依赖了 `AMDSEV` 树里的 out-of-tree KVM patch：

- `<AMDSEV_DIR>/patches/amdese_snp_host_latest_add_gpa_to_hpa_and_read_hpa.patch`

该 patch 在 `include/uapi/linux/kvm.h` 新增了两个 VM ioctl：

- `KVM_AMD_GPA_TO_HPA`
- `KVM_AMD_READ_GPA`

并在 `virt/kvm/kvm_main.c` 新增处理逻辑（`kvm_vm_ioctl` 分支）。

### 4.1 总体流程

1. guest 内核模块 `snp_sync_kmod` 分配共享页，并通过 `SNP_SYNC_IOC_GET_GPA` 向 guest 用户态返回共享页 GPA。  
2. guest 用户态 `guest_probe` 读取该 GPA（`shared_gpa`），并通过 `debugcon` 打印 `SNP_PROBE ... shared_gpa=0x...`。  
3. host preload 侧从日志解析 `shared_gpa`。  
4. host 在 QEMU 进程内找到 VM fd（`anon_inode:kvm-vm`），调用 `KVM_AMD_GPA_TO_HPA` 翻译 GPA。  
5. 返回结果中同时给出 `hpa` 和（可能存在的）`hva`。  
6. 若 `hva != 0`，host 直接走 HVA 映射（preload 同进程路径，最优）；否则回退到 `hpa_reader` 设备映射 HPA。  

### 4.2 Guest 侧导出 shared GPA（代码片段）

代码位置：
- `src/kmod_guest/snp_sync_kmod.c`
- `src/guest_probe.c`

```c
/* snp_sync_kmod.c */
if (cmd == SNP_SYNC_IOC_GET_GPA) {
    __u64 gpa = (__u64)sync_phys;
    if (copy_to_user((__u64 __user *)arg, &gpa, sizeof(gpa)))
        return -EFAULT;
    return 0;
}
```

```c
/* guest_probe.c */
int snp_fd = open("/dev/snp_sync", O_RDWR);
uint64_t shared_gpa = 0;
if (snp_fd >= 0) {
  if (ioctl(snp_fd, _IOR(0xB3u, 0x01, uint64_t), &shared_gpa) == 0) {
    ...
  }
}
```

### 4.3 Host 侧执行 GPA->HPA 翻译（代码片段）

代码位置：
- `src/host_runner_modes/common_runtime.c`
- `src/host_runner_preload_shared.h`

```c
int translate_gpa_to_hpa(int vm_fd, uint64_t gpa, uint64_t *hpa_out) {
  struct kvm_amd_gpa_to_hpa p;
  memset(&p, 0, sizeof(p));
  p.gpa = gpa & ~(PAGE_SZ - 1ULL);

  if (ioctl(vm_fd, KVM_AMD_GPA_TO_HPA, &p) != 0)
    return -1;
  if (p.ret != 0)
    return -1;
  *hpa_out = p.hpa & ~(PAGE_SZ - 1ULL);
  return 0;
}
```

共享页映射时同时读取 `hpa/hva`：

```c
if (ioctl(vm_fd, KVM_AMD_GPA_TO_HPA, &p) != 0)
  return NULL;
...
shared_hpa = p.hpa & ~(PAGE_SZ - 1ULL);
shared_hva = p.hva & ~(PAGE_SZ - 1ULL);

if (shared_hva != 0) {
  return (volatile uint64_t *)(uintptr_t)shared_hva;
}
```

### 4.4 你这份 patch 的关键点（为什么必须）

从 patch 逻辑看，`kvm_amd_vm_gpa_to_hpa()` 专门处理了 SNP + `guest_memfd` 私有页场景：

- 私有页不再可靠对应 userspace shared-side HVA
- patch 中通过 `kvm_gmem_get_pfn()` 获取真实 private-side PFN
- 因此能返回正确 `hpa`（并在 private 情况下 `hva=0`）

这正是你实验能在 SNP 私有内存语义下完成 GPA->HPA 翻译的关键。

### 4.5 与 `KVM_AMD_READ_GPA` 的关系

你的 host 采样主路径 `measure_line_ex()` 直接走 `KVM_AMD_READ_GPA`，本身按 GPA 发起读取与计时：

```c
p.gpa = page_gpa + (uint64_t)line * LINE_SZ;
p.mode = mode;
ioctl(vm_fd, KVM_AMD_READ_GPA, &p);
return p.tsc_delta;
```

所以：

- `GPA->HPA` 主要用于映射共享页、元数据记录、和一些辅助路径
- `READ_GPA` 承担了核心采样（H0/H1 cycles）逻辑

## 5. 两种机制的核心差异

- Coherence：
  - 重点在 cache coherence 相关状态变化
  - 常用 cacheable 读路径
  - 观测的是一致性驱逐/失配效果

- Contention：
  - 重点在 DRAM 层竞争
  - 明确使用 `NOCACHE` + guest 侧 flush+load
  - 观测的是 row-buffer / 内存总线竞争效果

## 6. 当前脚本入口（复现实验）

- Coherence 采集（4.2-A）：
  - `sudo -E python3 src/scripts/run_42a.py`
- Contention 采集（4.2-B）：
  - `sudo -E python3 src/scripts/run_42b.py`

脚本会输出到 `result/ch4/exp4_2_a_<timestamp>` 与 `result/ch4/exp4_2_b_<timestamp>`（默认时间戳目录）。
