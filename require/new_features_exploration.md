# 新特征探索总结

## 已发现的特征

### 1. Baseline一致性 (Baseline Consistent) ✓✓✓
**定义：** 所有页面的baseline_hits值相同

**效果：**
- 满足条件的clusters: 3/20
- Oracle在其中: YES (rank 3)
- **独特性：高**

**稳定性：** 跨实验稳定
- Exp1: Oracle所有页面baseline=1（一致）
- Exp2: Oracle所有页面baseline=1（一致）
- Exp3: Oracle所有页面baseline=3（一致）

**推荐：** ✓ 强烈推荐使用

---

### 2. Score一致性 (Score Consistent) ✓✓
**定义：** 所有页面的score (trigger_hits - baseline_hits) 相同

**效果：**
- 满足条件的clusters: 3/20
- Oracle在其中: YES (rank 3, score=97)
- **独特性：高**

**原理：**
- Score = trigger_hits - baseline_hits
- Oracle: 100 - 3 = 97 (所有页面相同)
- 这是baseline_consistent的衍生特征

**推荐：** ✓ 可以作为辅助特征

---

### 3. 完美触发率 (Perfect Trigger) ✓
**定义：** 所有页面trigger_hits = 100

**效果：**
- 满足条件的clusters: 17/20
- Oracle在其中: YES
- **独特性：低**（太多clusters满足）

**推荐：** △ 作为基础过滤条件

---

### 4. 低Baseline比率 (Low Baseline Ratio) ✓
**定义：** avg_baseline / avg_trigger < 0.05

**效果：**
- 满足条件的clusters: 14/20
- Oracle在其中: YES (ratio=0.03)
- **独特性：中等**

**推荐：** △ 可以作为辅助特征

---

### 5. 紧凑Cluster (Compact Cluster) ✓
**定义：** 地址跨度 < 12 pages (48KB)

**效果：**
- 满足条件的clusters: 17/20
- Oracle在其中: YES (gap=9 pages)
- **独特性：低**

**原理：** Te0只有1KB (4页)，加上一些gap，应该很紧凑

**推荐：** △ 作为基础过滤条件

---

### 6. Cluster Size ✓✓
**定义：** 4 <= size <= 10

**效果：**
- Te0只有1KB = 4页
- 加上Te1/Te2/Te3，最多10页
- 大clusters (>10) 不可能是Te0

**推荐：** ✓ 强烈推荐使用（已在当前策略中）

---

### 7. 地址范围 (Address Range) △
**定义：** 检查是否在特定内存区域

**效果：**
- Oracle在 0x101c00000 - 0x101d00000 范围
- 但这个范围是程序特定的，不通用

**推荐：** ✗ 不推荐（缺乏通用性）

---

## 组合特征分析

### 组合1: Baseline_consistent + Size (4-10)
**当前策略使用**

**效果：**
- 非常好的区分度
- Oracle排名第1

**推荐：** ✓✓✓ 当前最佳策略

---

### 组合2: Score_consistent + Size (4-10)
**与组合1类似**

**效果：**
- 应该和baseline_consistent效果相同
- 因为score = trigger - baseline

**推荐：** ✓ 可以作为baseline_consistent的替代

---

### 组合3: Trigger=100 + Baseline<5 + Gap<12 + Size(4-10)
**多重过滤**

**效果：**
- 满足条件的clusters: 11/20
- Oracle在其中: YES
- 区分度中等

**推荐：** △ 可以作为fallback策略

---

## 新特征建议

### 1. Baseline标准差 (Baseline Std Dev)
**定义：** 计算cluster内所有页面baseline_hits的标准差

**预期：**
- Oracle: std=0 (所有页面相同)
- 其他: std>0 (页面不同)

**优势：**
- 比baseline_consistent更精确
- 可以量化一致性程度

---

### 2. 地址连续性 (Address Continuity)
**定义：** 检查cluster内页面地址是否连续（gap=0）

**预期：**
- Te0的4个页面应该是连续的
- 如果有gap，说明可能不是Te0

**实现：**
```python
gaps = [cluster_pages[i+1] - cluster_pages[i] for i in range(len(cluster_pages)-1)]
max_gap = max(gaps) // 4096 if gaps else 0
is_continuous = max_gap <= 1  # 允许1页的gap
```

---

### 3. Coherence模式 (Coherence Pattern)
**定义：** 分析coherence测试中的cache line访问模式

**预期：**
- Te0: 某些cache lines有强信号，其他lines弱信号
- 其他页面: 所有lines信号均匀

**实现：**
- 已经在correlation测试中使用
- 可以进一步分析line_deltas的分布

---

### 4. 多实验一致性 (Cross-Experiment Consistency)
**定义：** 检查同一个cluster在多次实验中是否都出现

**预期：**
- Te0应该在所有实验中都被检测到
- 随机的false positives不会每次都出现

**实现：**
- 需要保存历史实验结果
- 比较不同实验的cluster列表

---

## 推荐的最终策略

### 主要特征（高权重）
1. **Baseline_consistent** (bonus=30)
2. **Cluster size** (4-10页，penalty for >10)
3. **Coherence SNR** (60%权重)

### 辅助特征（中等权重）
4. **Score_consistent** (bonus=10)
5. **Low baseline ratio** (<0.05, bonus=5)

### 过滤条件（必须满足）
6. **Trigger_hits = 100** (所有页面)
7. **Compact cluster** (gap < 12 pages)

### 评分公式
```python
# Base score
base_score = coherence_snr * 0.6 + correlation_score * 0.4

# Size penalty
if cluster_size > 10:
    size_penalty = 0.5
elif cluster_size > 6:
    size_penalty = 0.8
else:
    size_penalty = 1.0

# Baseline features
baseline_consistent = len(set(baseline_hits)) == 1
score_consistent = len(set(scores)) == 1
baseline_ratio = avg_baseline / avg_trigger

# Bonuses
bonus = 0
if baseline_consistent and 4 <= cluster_size <= 10:
    bonus += 30
if score_consistent:
    bonus += 10
if baseline_ratio < 0.05:
    bonus += 5

# Final score
combined_score = base_score * size_penalty + bonus
```

## 总结

**最有价值的新特征：**
1. ✓✓✓ Baseline_consistent (已实现)
2. ✓✓ Score_consistent (易于添加)
3. ✓ Baseline ratio (易于添加)

**建议下一步：**
1. 添加score_consistent和baseline_ratio作为辅助特征
2. 测试新的组合策略
3. 验证跨实验的稳定性
