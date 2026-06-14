# Ch5 byte8/byte12 密钥恢复实验指令

本文档记录在 `byte 8` 和 `byte 12` 上复刻 AES T-Table 部分密钥恢复实验的推荐命令。流程与当前 `byte 0`、`byte 4` 实验一致，分为三步：

1. 离线采集训练数据
2. 训练 Gaussian template 模型
3. 在线采集并恢复密钥候选

固定真实密钥为：

```text
5a112233445566778899aabbccddeeff
```

其中：

- `byte 8` 的真值为 `0x88`
- `byte 12` 的真值为 `0xcc`

## 1. 通用参数

当前实验复用已经定位好的 `Te0` 怀疑范围：

```text
<COHERE_REPO>/suspected_gpa_range_53_corrected.json
```

训练采集参数沿用 `byte 4` 已有配置：

```text
--entries all
--samples-per-entry 16
--contention-burst 16
--feature-topk 12
--aes-sync-phase1-repeats 12
--noise-lines ""
```

在线恢复参数沿用已有 Gaussian batch 配置：

```text
--samples-total 4096
--contention-burst 16
--feature-topk 12
--aes-sync-phase1-repeats 12
--noise-lines ""
```

建议先各跑 `16` 轮训练采集，再各跑 `64` 轮在线恢复统计。若时间紧，可以先把在线恢复的 `--runs 64` 改为 `--runs 8` 或 `--runs 16` 做快速验证。

## 2. byte8 实验

### 2.1 离线采集训练数据

```bash
sudo -E python3 src/scripts/run_53_signal_collect_batch.py \
  --runs 16 \
  --batch-outdir result/ch5/exp5_3_signal_batch_byte8 \
  -- \
  --suspected-range-json <COHERE_REPO>/suspected_gpa_range_53_corrected.json \
  --byte-pos 8 \
  --entries all \
  --samples-per-entry 16 \
  --contention-burst 16 \
  --feature-topk 12 \
  --aes-sync-phase1-repeats 12 \
  --noise-lines ""
```

### 2.2 训练 Gaussian template

```bash
python3 src/scripts/train_53_gaussian_template.py \
  --batch-dir result/ch5/exp5_3_signal_batch_byte8 \
  --byte-pos 8 \
  --jobs 64 \
  --out-json result/ch5/exp5_3_signal_batch_byte8/gaussian_template_model_byte8_v1.json
```

### 2.3 在线采集并恢复

```bash
sudo -E python3 src/scripts/run_53_online_collect_recover_batch.py \
  --runs 64 \
  --batch-outdir result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte8 \
  --model-json result/ch5/exp5_3_signal_batch_byte8/gaussian_template_model_byte8_v1.json \
  --byte-positions 8 \
  --top-k 16 \
  --true-key-hex 5a112233445566778899aabbccddeeff \
  -- \
  --suspected-range-json <COHERE_REPO>/suspected_gpa_range_53_corrected.json \
  --byte-pos 8 \
  --samples-total 4096 \
  --contention-burst 16 \
  --feature-topk 12 \
  --aes-sync-phase1-repeats 12 \
  --noise-lines ""
```

## 3. byte12 实验

### 3.1 离线采集训练数据

```bash
sudo -E python3 src/scripts/run_53_signal_collect_batch.py \
  --runs 16 \
  --batch-outdir result/ch5/exp5_3_signal_batch_byte12 \
  -- \
  --suspected-range-json <COHERE_REPO>/suspected_gpa_range_53_corrected.json \
  --byte-pos 12 \
  --entries all \
  --samples-per-entry 16 \
  --contention-burst 16 \
  --feature-topk 12 \
  --aes-sync-phase1-repeats 12 \
  --noise-lines ""
```

### 3.2 训练 Gaussian template

```bash
python3 src/scripts/train_53_gaussian_template.py \
  --batch-dir result/ch5/exp5_3_signal_batch_byte12 \
  --byte-pos 12 \
  --jobs 64 \
  --out-json result/ch5/exp5_3_signal_batch_byte12/gaussian_template_model_byte12_v1.json
```

### 3.3 在线采集并恢复

```bash
sudo -E python3 src/scripts/run_53_online_collect_recover_batch.py \
  --runs 64 \
  --batch-outdir result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte12 \
  --model-json result/ch5/exp5_3_signal_batch_byte12/gaussian_template_model_byte12_v1.json \
  --byte-positions 12 \
  --top-k 16 \
  --true-key-hex 5a112233445566778899aabbccddeeff \
  -- \
  --suspected-range-json <COHERE_REPO>/suspected_gpa_range_53_corrected.json \
  --byte-pos 12 \
  --samples-total 4096 \
  --contention-burst 16 \
  --feature-topk 12 \
  --aes-sync-phase1-repeats 12 \
  --noise-lines ""
```

## 4. 结果检查

在线恢复完成后，主要看以下 CSV：

```bash
head -20 result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte8/batch_recovery_summary.csv
head -20 result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte12/batch_recovery_summary.csv
```

统计 Top-k 命中率可以用下面的一次性命令：

```bash
python3 - <<'PY'
import csv
from pathlib import Path

for path in [
    Path("result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte8/batch_recovery_summary.csv"),
    Path("result/ch5/exp5_3_online_collect_recover_gaussian_batch_byte12/batch_recovery_summary.csv"),
]:
    if not path.exists():
        print(f"{path}: missing")
        continue
    rows = list(csv.DictReader(path.open()))
    ok_rows = [
        r for r in rows
        if r.get("collect_returncode") == "0"
        and r.get("recover_returncode") == "0"
        and str(r.get("true_rank_in_topk", "")).strip()
    ]
    ranks = [int(r["true_rank_in_topk"]) for r in ok_rows]
    total = len(ranks)
    print(f"\n{path}")
    print(f"valid runs: {total}/{len(rows)}")
    for k in [1, 3, 5, 8, 16]:
        hit = sum(1 for rank in ranks if rank <= k)
        pct = (100.0 * hit / total) if total else 0.0
        print(f"Top-{k}: {hit}/{total} = {pct:.2f}%")
    if ranks:
        ranks_sorted = sorted(ranks)
        mid = total // 2
        median = ranks_sorted[mid] if total % 2 else (ranks_sorted[mid - 1] + ranks_sorted[mid]) / 2
        print(f"avg rank: {sum(ranks) / total:.2f}")
        print(f"median rank: {median}")
PY
```

## 5. 注意事项

- `byte 8` 和 `byte 12` 虽然与 `byte 0/4` 同属 `Te0` 路径，但仍应分别训练独立模型，不建议直接复用 `byte 0` 或 `byte 4` 的模型。
- 当前 byte4 在线结果显示 Top-1 不稳定，但真实 key 通常能进入 Top-k；因此建议报告 `Top-1/Top-3/Top-5/Top-8/Top-16`，不要只看单轮 Top-1。
- 如果在线恢复命令运行时间过长，先用 `--runs 8` 做 smoke test，确认采集和恢复链路正常后再跑 `--runs 64`。
