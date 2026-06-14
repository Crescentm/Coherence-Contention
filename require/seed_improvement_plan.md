# Seed过程改进方案

## 问题分析

### 当前Seed流程的问题

从实验 `exp5_3_seed_20260329_200159` 的结果分析：

1. **NPT Discovery找到2230个页面，都是score=12**
   - 无法区分哪个是真正的Te0页面
   - 正确页面(0x101c5e000)排在第79位

2. **Clustering算法选择错误**
   ```python
   def score_of(cluster: list[int]) -> tuple[int, int, int]:
       s = sum(max(0, page_score.get(p, 0)) for p in cluster)
       count = len(cluster)
       span = cluster[-1] - cluster[0]
       return (s, count, -span)  # 优先总分，其次数量，最后紧凑度
   ```

   **问题**：
   - 选择了0x1ee0000附近的cluster（9个页面，总分108）
   - 而不是0x101c5e000（单个页面，总分12）
   - 算法偏好"页面多、总分高"的cluster

3. **Discovery轮数不足**
   - 只有12轮，每轮16次trigger
   - 总共192次AES调用，不足以区分信号

### 根本原因

**NPT A/D bit机制的局限性**：
- NPT只能检测"是否访问"，不能检测"访问频率"
- 12轮discovery中，很多页面都被访问了12次（满分）
- 无法区分"偶尔访问"和"频繁访问"

---

## 改进方案

### 方案1：增加Discovery轮数和触发次数 🔴 高优先级

**原理**：更多轮次可以让真正的热点页面脱颖而出。

```python
# 当前配置
--discover-rounds 12
--trigger-requests-per-round 16
# 总计: 12 * 16 = 192次AES调用

# 改进配置
--discover-rounds 100
--trigger-requests-per-round 50
# 总计: 100 * 50 = 5000次AES调用
```

**预期效果**：
- Te0页面应该在100轮中都被hit（score=100）
- 其他偶然访问的页面score会分散（20-80）
- 更容易区分真正的热点

**实施**：
```bash
sudo -E python3 src/scripts/run_53_seed_range.py \
    --discover-rounds 100 \
    --trigger-requests-per-round 50 \
    --outdir result/ch5/exp5_3_seed_improved
```

---

### 方案2：改进Clustering算法 🔴 高优先级

**问题**：当前算法偏好"页面多、总分高"的cluster。

**改进**：优先选择"单页面、高分"的候选。

```python
def select_cluster_pages_v2(ranking: list[dict[str, int]], args: argparse.Namespace) -> list[int]:
    """改进的clustering算法"""
    if not ranking:
        raise RuntimeError("empty NPT ranking result")

    # 过滤：score >= min_score 且 trigger > baseline
    pos = [
        row for row in ranking
        if int(row["score"]) >= args.min_score
        and int(row["trigger_hits"]) > int(row["baseline_hits"])
    ]

    if not pos:
        pos = ranking[:args.top_pages]

    page_score = {int(r["page_gpa"]): int(r["score"]) for r in pos}
    pages = sorted(page_score.keys())

    if not pages:
        raise RuntimeError("no candidate pages after filtering")

    # 构建clusters
    gap_bytes = max(0, args.cluster_gap_pages) * PAGE_SZ
    clusters: list[list[int]] = []
    cur: list[int] = [pages[0]]

    for p in pages[1:]:
        if p - cur[-1] <= max(PAGE_SZ, gap_bytes):
            cur.append(p)
        else:
            clusters.append(cur)
            cur = [p]
    clusters.append(cur)

    # 改进的评分函数
    def score_of_v2(cluster: list[int]) -> tuple[float, int, int]:
        """
        优先级：
        1. 平均分（而非总分）
        2. 最高单页分数
        3. 紧凑度（负span）
        """
        scores = [page_score.get(p, 0) for p in cluster]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores) if scores else 0
        span = cluster[-1] - cluster[0]

        # 返回：(平均分, 最高分, -span)
        return (avg_score, max_score, -span)

    # 选择最佳cluster
    best = max(clusters, key=score_of_v2)

    # 额外验证：如果最佳cluster只有1个页面且分数很高，直接返回
    if len(best) == 1 and page_score.get(best[0], 0) >= args.discover_rounds * 0.8:
        print(f"[cluster] Single high-score page detected: 0x{best[0]:x} score={page_score[best[0]]}")
        return best

    return best
```

**关键改进**：
1. 使用**平均分**而非总分
2. 考虑**最高单页分数**
3. 单页面高分优先

---

### 方案3：多候选验证 🟡 中优先级

**原理**：不要只选一个cluster，而是对top N个候选都进行验证。

```python
def select_multiple_candidate_clusters(
    ranking: list[dict[str, int]],
    args: argparse.Namespace,
    top_n: int = 5
) -> list[list[int]]:
    """返回top N个候选cluster"""
    if not ranking:
        return []

    pos = [
        row for row in ranking
        if int(row["score"]) >= args.min_score
        and int(row["trigger_hits"]) > int(row["baseline_hits"])
    ]

    if not pos:
        pos = ranking[:args.top_pages]

    page_score = {int(r["page_gpa"]): int(r["score"]) for r in pos}
    pages = sorted(page_score.keys())

    # 构建所有clusters
    gap_bytes = max(0, args.cluster_gap_pages) * PAGE_SZ
    clusters: list[list[int]] = []
    cur: list[int] = [pages[0]]

    for p in pages[1:]:
        if p - cur[-1] <= max(PAGE_SZ, gap_bytes):
            cur.append(p)
        else:
            clusters.append(cur)
            cur = [p]
    clusters.append(cur)

    # 评分并排序
    def score_of(cluster: list[int]) -> tuple[float, int, int]:
        scores = [page_score.get(p, 0) for p in cluster]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores) if scores else 0
        span = cluster[-1] - cluster[0]
        return (avg_score, max_score, -span)

    clusters_sorted = sorted(clusters, key=score_of, reverse=True)

    # 返回top N
    return clusters_sorted[:top_n]


def verify_candidates_with_coherence(
    npt: NptCtlClient,
    candidates: list[list[int]],
    te0_inpage_offset: int,
    args: argparse.Namespace
) -> dict[str, object]:
    """对每个候选cluster进行coherence验证"""
    results = []

    for i, cluster in enumerate(candidates):
        print(f"[verify] Candidate {i+1}/{len(candidates)}: {len(cluster)} pages")

        for page in cluster:
            te0_gpa = page + te0_inpage_offset

            # 快速coherence测试（8次采样）
            coherence_score = evaluate_page_coherence(npt, te0_gpa, args, reps=8)

            results.append({
                "cluster_id": i,
                "page_gpa": page,
                "te0_gpa": te0_gpa,
                "coherence_score": coherence_score,
            })

            print(f"  page=0x{page:x} coherence={coherence_score:.1f}")

    # 按coherence排序
    results.sort(key=lambda x: x["coherence_score"], reverse=True)

    return {
        "best_page": results[0]["page_gpa"],
        "best_te0_gpa": results[0]["te0_gpa"],
        "best_coherence": results[0]["coherence_score"],
        "all_results": results,
    }


def evaluate_page_coherence(
    npt: NptCtlClient,
    te0_gpa: int,
    args: argparse.Namespace,
    reps: int = 8
) -> float:
    """快速评估页面的coherence score"""
    # 简化版的line scan，只测量几条line
    test_lines = [0, 8, 15, 24, 32, 40, 48, 56, 63]  # 采样9条line

    max_delta = 0.0

    for line in test_lines:
        line_gpa = (te0_gpa & ~(PAGE_SZ - 1)) + line * 64

        h0_samples = []
        h1_samples = []

        for _ in range(reps):
            # Baseline
            t0 = npt.read_gpa_tsc(line_gpa, mode=4)  # CIPHERTEXT_CACHEABLE
            h0_samples.append(t0)

            # Trigger
            _ = aes_request(args.host, args.aes_port, os.urandom(16), args.sock_timeout_s)
            t1 = npt.read_gpa_tsc(line_gpa, mode=4)
            h1_samples.append(t1)

        h0_median = statistics.median(h0_samples)
        h1_median = statistics.median(h1_samples)
        delta = h1_median - h0_median

        if delta > max_delta:
            max_delta = delta

    return max_delta
```

**使用方式**：
```python
# 在seed脚本中
candidates = select_multiple_candidate_clusters(ranking, args, top_n=5)
verification = verify_candidates_with_coherence(npt, candidates, te0_inpage_offset, args)

print(f"[seed] Best verified page: 0x{verification['best_page']:x}")
print(f"[seed] Coherence score: {verification['best_coherence']:.1f}")
```

---

### 方案4：使用Guest Oracle辅助 🟢 低优先级

**原理**：Guest已经输出了正确的GPA，可以用来验证seed结果。

```python
def parse_guest_oracle_from_console(console_log_path: Path) -> dict[str, int] | None:
    """从console log中解析guest输出的oracle信息"""
    if not console_log_path.exists():
        return None

    with console_log_path.open("r") as f:
        content = f.read()

    # 查找: victim_aes_oracle: ... te0_gpa=0x101c5ef60 te0_page_gpa=0x101c5e000
    import re
    pattern = r"victim_aes_oracle:.*te0_gpa=(0x[0-9a-fA-F]+).*te0_page_gpa=(0x[0-9a-fA-F]+)"
    match = re.search(pattern, content)

    if not match:
        return None

    return {
        "te0_gpa": int(match.group(1), 16),
        "te0_page_gpa": int(match.group(2), 16),
    }


def verify_seed_result_with_oracle(
    selected_cluster: list[int],
    console_log_path: Path
) -> dict[str, object]:
    """用oracle验证seed结果"""
    oracle = parse_guest_oracle_from_console(console_log_path)

    if oracle is None:
        return {"oracle_available": False}

    oracle_page = oracle["te0_page_gpa"]

    # 检查oracle page是否在selected cluster中
    is_correct = oracle_page in selected_cluster

    if is_correct:
        print(f"[oracle] ✓ Seed result CORRECT: oracle page 0x{oracle_page:x} in cluster")
    else:
        print(f"[oracle] ✗ Seed result WRONG: oracle page 0x{oracle_page:x} NOT in cluster")
        print(f"[oracle]   Selected cluster: {[f'0x{p:x}' for p in selected_cluster]}")

    return {
        "oracle_available": True,
        "oracle_te0_gpa": oracle["te0_gpa"],
        "oracle_page_gpa": oracle_page,
        "seed_correct": is_correct,
        "selected_cluster": selected_cluster,
    }
```

---

### 方案5：自适应Discovery 🟢 低优先级

**原理**：动态调整discovery轮数，直到找到明确的候选。

```python
def adaptive_npt_discovery(
    npt: NptCtlClient,
    args: argparse.Namespace,
    scan_start_gpa: int,
    scan_end_gpa: int,
    outdir: Path,
    min_rounds: int = 20,
    max_rounds: int = 200,
    convergence_threshold: float = 0.8
) -> list[dict[str, int]]:
    """自适应NPT discovery"""
    disc_dir = outdir / "npt_seed"
    disc_dir.mkdir(parents=True, exist_ok=True)

    trig_hits: dict[int, int] = {}
    base_hits: dict[int, int] = {}

    for r in range(max_rounds):
        # ... 执行一轮discovery（同原逻辑）

        # 每10轮检查一次收敛
        if r >= min_rounds and (r + 1) % 10 == 0:
            # 计算当前排名
            ranking = compute_ranking(trig_hits, base_hits)

            if len(ranking) == 0:
                continue

            # 检查top1和top2的分数差距
            if len(ranking) >= 2:
                top1_score = ranking[0]["score"]
                top2_score = ranking[1]["score"]

                # 如果top1明显领先（超过80%的轮数）
                if top1_score >= (r + 1) * convergence_threshold and top1_score > top2_score * 1.5:
                    print(f"[adaptive] Converged at round {r+1}: top1_score={top1_score}, top2_score={top2_score}")
                    break

    # 返回最终ranking
    return compute_ranking(trig_hits, base_hits)
```

---

## 实施优先级

### Phase 1: 立即实施（今天）

1. **✅ 增加discovery轮数**
   ```bash
   sudo -E python3 src/scripts/run_53_seed_range.py \
       --discover-rounds 100 \
       --trigger-requests-per-round 50 \
       --outdir result/ch5/exp5_3_seed_100rounds
   ```

2. **✅ 改进clustering算法**
   - 修改`select_cluster_pages()`函数
   - 使用平均分而非总分
   - 优先单页面高分

### Phase 2: 短期实施（1-2天）

3. **🔄 多候选验证**
   - 实现`select_multiple_candidate_clusters()`
   - 实现`verify_candidates_with_coherence()`
   - 对top 5个cluster都进行验证

4. **🔄 Oracle验证**
   - 实现`parse_guest_oracle_from_console()`
   - 在seed结束时验证结果

### Phase 3: 长期优化（1周）

5. **🔮 自适应discovery**
   - 实现`adaptive_npt_discovery()`
   - 动态调整轮数

---

## 代码修改清单

### 文件: `src/scripts/run_53_seed_range.py`

#### 修改1: 改进clustering算法（line 584-622）

```python
def select_cluster_pages_v2(ranking: list[dict[str, int]], args: argparse.Namespace) -> list[int]:
    """改进的clustering算法：优先平均分和单页高分"""
    if not ranking:
        raise RuntimeError("empty NPT ranking result")

    pos = [
        row for row in ranking
        if int(row["score"]) >= args.min_score
        and int(row["trigger_hits"]) > int(row["baseline_hits"])
    ]

    if not pos:
        pos = [row for row in ranking if int(row["score"]) > 0]
    if not pos:
        pos = ranking[:max(1, args.top_pages)]

    pos = pos[:max(1, args.top_pages)]
    page_score = {int(r["page_gpa"]): int(r["score"]) for r in pos}
    pages = sorted(page_score.keys())

    if not pages:
        raise RuntimeError("no candidate pages after filtering")

    # 构建clusters
    gap_bytes = max(0, args.cluster_gap_pages) * PAGE_SZ
    clusters: list[list[int]] = []
    cur: list[int] = [pages[0]]

    for p in pages[1:]:
        if p - cur[-1] <= max(PAGE_SZ, gap_bytes):
            cur.append(p)
        else:
            clusters.append(cur)
            cur = [p]
    clusters.append(cur)

    # 改进的评分函数
    def score_of_v2(cluster: list[int]) -> tuple[float, int, int]:
        scores = [page_score.get(p, 0) for p in cluster]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores) if scores else 0
        span = cluster[-1] - cluster[0]

        # 优先级：平均分 > 最高分 > 紧凑度
        return (avg_score, max_score, -span)

    # 选择最佳cluster
    best = max(clusters, key=score_of_v2)

    # 打印调试信息
    print(f"[cluster] Found {len(clusters)} clusters")
    for i, c in enumerate(sorted(clusters, key=score_of_v2, reverse=True)[:5]):
        scores = [page_score.get(p, 0) for p in c]
        avg = sum(scores) / len(scores)
        print(f"  Cluster {i+1}: {len(c)} pages, avg_score={avg:.1f}, max_score={max(scores)}, pages={[f'0x{p:x}' for p in c[:3]]}")

    return best
```

#### 修改2: 添加Oracle验证（新增函数）

```python
def parse_guest_oracle_from_console(console_log_path: Path) -> dict[str, int] | None:
    """从console log中解析guest输出的oracle信息"""
    if not console_log_path.exists():
        return None

    try:
        with console_log_path.open("r") as f:
            content = f.read()
    except Exception:
        return None

    import re
    pattern = r"victim_aes_oracle:.*te0_gpa=(0x[0-9a-fA-F]+).*te0_page_gpa=(0x[0-9a-fA-F]+)"
    match = re.search(pattern, content)

    if not match:
        return None

    return {
        "te0_gpa": int(match.group(1), 16),
        "te0_page_gpa": int(match.group(2), 16),
    }


def verify_seed_with_oracle(
    cluster_pages: list[int],
    console_log_path: Path
) -> dict[str, object]:
    """用oracle验证seed结果"""
    oracle = parse_guest_oracle_from_console(console_log_path)

    if oracle is None:
        return {"oracle_available": False}

    oracle_page = oracle["te0_page_gpa"]
    is_correct = oracle_page in cluster_pages

    result = {
        "oracle_available": True,
        "oracle_te0_gpa": f"0x{oracle['te0_gpa']:x}",
        "oracle_page_gpa": f"0x{oracle_page:x}",
        "seed_correct": is_correct,
        "selected_cluster": [f"0x{p:x}" for p in cluster_pages],
    }

    if is_correct:
        print(f"[oracle] ✓ CORRECT: oracle page 0x{oracle_page:x} in cluster")
    else:
        print(f"[oracle] ✗ WRONG: oracle page 0x{oracle_page:x} NOT in cluster")
        print(f"[oracle]   Selected: {result['selected_cluster']}")

    return result
```

#### 修改3: 在main()中调用验证（line 714之后）

```python
# 在 cluster_pages = select_cluster_pages(ranking, args) 之后添加：

# Oracle验证
console_log = vm_dir / "qemu_console.log"
oracle_verification = verify_seed_with_oracle(cluster_pages, console_log)

# 保存验证结果
write_json(
    outdir / "oracle_verification.json",
    oracle_verification
)
```

---

## 测试验证

### 测试1: 增加轮数

```bash
cd <COHERE_REPO>

# 运行改进的seed
sudo -E python3 src/scripts/run_53_seed_range.py \
    --discover-rounds 100 \
    --trigger-requests-per-round 50 \
    --outdir result/ch5/exp5_3_seed_100rounds

# 检查结果
cat result/ch5/exp5_3_seed_100rounds/suspected_gpa_range_53.json | grep -E "cluster_pages|oracle"
cat result/ch5/exp5_3_seed_100rounds/oracle_verification.json
```

### 测试2: 对比原版和改进版

```bash
# 查看原版seed的cluster选择
cat result/ch5/exp5_3_seed_20260329_200159/suspected_gpa_range_53.json | jq '.cluster_pages'

# 查看改进版的cluster选择
cat result/ch5/exp5_3_seed_100rounds/suspected_gpa_range_53.json | jq '.cluster_pages'

# 对比ranking
head -20 result/ch5/exp5_3_seed_20260329_200159/npt_seed/seed_page_ranking.csv
head -20 result/ch5/exp5_3_seed_100rounds/npt_seed/seed_page_ranking.csv
```

---

## 预期效果

### 改进前（12轮）
```
Top pages: 所有score=12，无法区分
Cluster: 0x1ee0000附近（9个页面，错误）
Oracle: 0x101c5e000（第79位）
```

### 改进后（100轮）
```
Top pages:
  - 0x101c5e000: score=100 (正确)
  - 其他页面: score=20-60 (偶然访问)
Cluster: 0x101c5e000（单页面，正确）
Oracle: ✓ 验证通过
```

---

## 总结

**核心改进**：
1. 增加discovery轮数（12→100）
2. 改进clustering算法（总分→平均分）
3. 添加Oracle验证

**预期提升**：
- Seed准确率：从0%提升到>90%
- 后续实验成功率：显著提高

**实施成本**：
- 时间成本：seed时间从2分钟增加到10分钟
- 代码修改：约100行
- 风险：低（向后兼容）
