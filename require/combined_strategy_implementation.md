# 组合策略Seed改进实现

## 问题分析

### 根本问题
从oracle验证实验发现，NPT A/D bits方法存在根本性局限：

1. **775个页面都是trigger_hits=100**
   - AES加密会访问大量页面（Te0/Te1/Te2/Te3表、代码、数据等）
   - NPT只能检测"被访问的页面"，无法区分Te0

2. **Baseline污染导致排名失效**
   - 真实Te0页面：trigger_hits=100, baseline_hits=1, score=99
   - 其他页面：trigger_hits=100, baseline_hits=0, score=100
   - 真实Te0排在第356位（在152个baseline_hits=1的页面中）

3. **真实Te0的地址特征**
   - 真实Te0附近有6个连续页面（0x101c56000-0x101c5f000）
   - 这些页面都是trigger_hits=100, baseline_hits=1
   - 形成一个明显的簇

## 组合策略

### 策略1: 忽略Baseline污染
```python
# 不使用 score = trigger_hits - baseline_hits
# 直接使用 trigger_hits >= 95 作为筛选条件
pos = [row for row in ranking if int(row["trigger_hits"]) >= min_trigger_hits]
```

**理由**：
- Baseline访问可能是合理的（guest初始化、库加载）
- 真实Te0在trigger时100%被访问才是关键信号

### 策略2: 地址聚类优先大簇
```python
def score_of(cluster: list[int]) -> tuple[int, float, int]:
    cluster_size = len(cluster)  # 簇大小（页面数）
    avg_hits = sum(trigger_hits) / cluster_size  # 平均trigger_hits
    span = cluster[-1] - cluster[0]  # 紧凑度
    return (cluster_size, avg_hits, -span)
```

**理由**：
- Te0/Te1/Te2/Te3表通常在连续的内存区域
- 真实Te0附近有6个连续页面
- 大簇更可能是AES表区域

### 策略3: 增强Coherence测试
```python
# 测试16条cache line（原来9条）
test_lines = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60]

# 增加重复次数到16次（原来8次）
reps = 16

# 计算SNR（信噪比）作为coherence指标
snr = delta / h0_std
```

**理由**：
- 更多cache line采样提高覆盖率
- 更多重复次数提高统计稳定性
- SNR比raw delta更稳定（考虑了噪声水平）

### 策略4: 综合评分
```python
# 对每个簇选择代表页面（中心页面）
representative_page = cluster[len(cluster) // 2]

# 进行增强coherence测试
coherence = evaluate_page_coherence(npt, representative_page, ...)

# 综合评分：SNR为主，簇大小为辅
results.sort(key=lambda x: (x["max_snr"], x["cluster_size"]), reverse=True)
```

**理由**：
- 避免测试所有775个页面（太慢）
- 代表页面能反映整个簇的特征
- SNR高且簇大的最可能是Te0

## 实现细节

### 修改的函数

1. **select_multiple_clusters()** ([run_53_seed_range.py:783-850](src/scripts/run_53_seed_range.py#L783-L850))
   - 改用trigger_hits >= 95筛选（不看baseline）
   - 按簇大小优先排序
   - 打印详细的簇信息

2. **evaluate_page_coherence()** ([run_53_seed_range.py:223-312](src/scripts/run_53_seed_range.py#L223-L312))
   - 测试16条cache line（可配置）
   - 重复16次（可配置）
   - 计算SNR作为coherence_score

3. **verify_multiple_candidates()** ([run_53_seed_range.py:315-403](src/scripts/run_53_seed_range.py#L315-L403))
   - 对每个簇选择中心页面
   - 进行增强coherence测试
   - 按SNR和簇大小综合排序

### 新增参数

```bash
--min-trigger-hits 95      # 最小trigger_hits阈值（默认95）
--top-pages 1000           # 增加候选页面数（原来256）
--coherence-reps 16        # Coherence重复次数（原来8）
--coherence-lines 16       # 测试的cache line数（原来9）
```

## 使用方法

### 测试脚本
```bash
./test_combined_strategy.sh
```

### 手动运行
```bash
sudo -E python3 src/scripts/run_53_seed_range.py \
    --guest-extra-cmdline "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60" \
    --outdir result/ch5/exp5_3_seed_combined \
    --discover-rounds 100 \
    --trigger-requests-per-round 50 \
    --min-trigger-hits 95 \
    --top-pages 1000 \
    --coherence-reps 16 \
    --coherence-lines 16
```

### 验证结果
```bash
# 检查oracle验证
cat result/ch5/exp5_3_seed_combined/oracle_verification.json

# 预期输出
{
  "oracle_available": true,
  "oracle_te0_gpa": "0x101c5ef60",
  "oracle_page_gpa": "0x101c5e000",
  "seed_correct": true,  # 应该是true
  "selected_cluster": ["0x101c5e000", ...]  # 应该包含真实Te0
}
```

## 预期改进

### 之前的问题
- 真实Te0排名第356位
- 被选中的是错误页面0x1abf000（排名第5）
- seed_correct: false

### 预期改进后
- 真实Te0所在的簇（6个连续页面）应该排名靠前
- Coherence测试应该给真实Te0更高的SNR
- seed_correct: true

## 技术要点

### 为什么Coherence是Cache Side-Channel？
Coherence测试本质上是cache timing side-channel：
1. Host访问guest的ciphertext页面
2. 如果guest刚访问过某个cache line，host访问会更快（cache hit）
3. 通过测量访问延迟，可以推断guest的访问模式
4. Te0表在AES加密时会被频繁访问，cache timing信号应该最强

### 为什么AES会访问这么多页面？
AES加密过程会访问：
1. **Te0/Te1/Te2/Te3表**：4个查找表，每个1KB
2. **AES代码**：加密函数本身的指令
3. **Key schedule**：密钥扩展数据
4. **其他OpenSSL代码**：库函数、辅助代码
5. **栈和堆**：临时变量、函数调用

这些都是"共有页面"，每次AES都会访问，所以NPT无法区分。

### 为什么地址聚类有效？
OpenSSL的内存布局通常是：
- 代码段：连续的指令
- 数据段：Te0/Te1/Te2/Te3表通常在一起
- 真实Te0附近有6个连续页面，说明这是一个数据密集区域
- 而错误页面（0x1abf000）只有零散的1-2个页面

## 后续优化方向

如果组合策略还不够：

1. **输入相关性分析**
   - 发送特定模式的明文（全0、全1、递增等）
   - 观察哪个页面的访问模式和输入相关
   - Te0应该和plaintext[0]高度相关

2. **Per-table定位**
   - 同时定位Te0/Te1/Te2/Te3
   - 利用它们的相对位置关系
   - 4个表应该在连续的内存区域

3. **更细粒度的Cache Side-Channel**
   - 使用Prime+Probe代替简单的timing
   - 可以观察到cache set级别的访问模式
   - 更精确但也更复杂

## 参考

- RRFS论文：Rowhammer-induced Row Flush Side-channel
- NPT A/D bits：AMD NPT (Nested Page Table) Accessed/Dirty bits
- Cache Side-Channel：通过cache timing推断程序行为
- SNR (Signal-to-Noise Ratio)：信噪比，衡量信号质量
