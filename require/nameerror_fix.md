# NameError修复

## 错误信息
```
NameError: name 'ranking' is not defined
```

## 问题原因

在`verify_multiple_candidates()`函数中添加了baseline consistency检查代码：

```python
# Check baseline consistency
baseline_hits = []
for page_gpa in cluster_pages:
    # Find page in ranking
    for row in ranking:  # <-- ranking未定义
        if row['page_gpa'] == page_gpa:
            baseline_hits.append(row['baseline_hits'])
            break
```

但是`ranking`变量没有作为参数传递给函数。

## 修复方案

### 1. 修改函数签名

**文件:** `src/scripts/run_53_seed_range.py`
**位置:** Line 401

```python
# 修改前
def verify_multiple_candidates(
    npt: NptCtlClient,
    candidate_clusters: list[list[int]],
    te0_inpage_offset: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    max_candidates: int = 10,
) -> dict[str, object]:

# 修改后
def verify_multiple_candidates(
    npt: NptCtlClient,
    candidate_clusters: list[list[int]],
    te0_inpage_offset: int,
    host: str,
    aes_port: int,
    sock_timeout_s: float,
    ranking: list[dict[str, int]],  # <-- 添加ranking参数
    max_candidates: int = 10,
) -> dict[str, object]:
```

### 2. 修改函数调用

**文件:** `src/scripts/run_53_seed_range.py`
**位置:** Line 1215

```python
# 修改前
verification = verify_multiple_candidates(
    npt,
    candidate_clusters,
    te0["te0_inpage_offset"],
    runtime_host,
    args.aes_port,
    args.sock_timeout_s,
    max_candidates=max_test,
)

# 修改后
verification = verify_multiple_candidates(
    npt,
    candidate_clusters,
    te0["te0_inpage_offset"],
    runtime_host,
    args.aes_port,
    args.sock_timeout_s,
    ranking,  # <-- 传递ranking参数
    max_candidates=max_test,
)
```

## 验证

运行测试脚本验证修复：

```bash
python3 test_verify_params.py
```

输出：
```
✓ ranking参数已添加

函数签名:
  (npt: 'NptCtlClient', candidate_clusters: 'list[list[int]]',
   te0_inpage_offset: 'int', host: 'str', aes_port: 'int',
   sock_timeout_s: 'float', ranking: 'list[dict[str, int]]',
   max_candidates: 'int' = 10) -> 'dict[str, object]'
```

## 测试

现在可以运行完整测试：

```bash
bash test_combined_strategy.sh
```

修复后的代码应该能正常运行，不再出现NameError。
