# 自动生成Guest Cmdline改进

## 问题

之前使用`--suspected-range-json`时，需要手动指定`--guest-extra-cmdline`参数，包括：
- `nokaslr norandmaps`（禁用地址随机化）
- `oracle_te0=1 oracle_te0_vma=0x... oracle_te0_off=0x...`（oracle参数）

这很繁琐且容易出错。

## 解决方案

修改代码，让`--guest-extra-cmdline`自动从`suspected_gpa_range_53.json`中生成。

### 改动1: 修改run_53.py

**位置**: `maybe_sync_oracle_from_range_json()` 函数

**改动**:
```python
# 旧逻辑：只在用户手动启用oracle时才同步参数
if not oracle_enabled:
    return

# 新逻辑：自动从JSON生成完整cmdline
def maybe_sync_oracle_from_range_json(args):
    """
    自动从suspected-range JSON生成guest cmdline参数

    如果提供了--suspected-range-json:
    1. 自动添加nokaslr norandmaps（如果未指定）
    2. 自动添加oracle参数（从JSON读取te0信息）
    """
    # 读取JSON
    obj = json.loads(path.read_text())

    # 提取te0信息
    te0_vma = parse_u64(obj["te0_symbol_vma"])
    te0_off = parse_u64(obj["te0_inpage_offset"])

    # 生成cmdline
    tokens = []
    tokens.append("nokaslr")
    tokens.append("norandmaps")
    tokens.append("oracle_te0=1")
    tokens.append(f"oracle_te0_vma=0x{te0_vma:x}")
    tokens.append(f"oracle_te0_off=0x{te0_off:x}")

    args.guest_extra_cmdline = " ".join(tokens)
```

**效果**:
- 用户只需提供`--suspected-range-json`
- 不需要手动指定`--guest-extra-cmdline`
- 自动生成正确的oracle参数

### 改动2: 修改run_53_seed_range.py

**位置**: main()函数，生成`suspected_gpa_range_53.json`时

**改动**:
```python
# 生成完整的guest cmdline（包含oracle参数）
guest_cmdline_base = str(args.guest_extra_cmdline).strip()
if not guest_cmdline_base:
    guest_cmdline_base = "nokaslr norandmaps"

# 确保有nokaslr和norandmaps
cmdline_tokens = guest_cmdline_base.split()
if "nokaslr" not in cmdline_tokens:
    cmdline_tokens.insert(0, "nokaslr")
if "norandmaps" not in cmdline_tokens:
    cmdline_tokens.insert(1, "norandmaps")

# 添加oracle参数
cmdline_tokens.append("oracle_te0=1")
cmdline_tokens.append(f"oracle_te0_vma=0x{te0['te0_vma']:x}")
cmdline_tokens.append(f"oracle_te0_off=0x{te0['te0_inpage_offset']:x}")

guest_cmdline_full = " ".join(cmdline_tokens)

# 保存到JSON
result = {
    ...
    "guest_cmdline_extra": guest_cmdline_full,
    ...
}
```

**效果**:
- Seed生成的JSON包含完整的guest cmdline
- 包括oracle参数，可以直接使用

---

## 使用方法

### 之前（繁琐）

```bash
# 1. 运行seed
sudo -E python3 src/scripts/run_53_seed_range.py \
    --outdir result/ch5/exp5_3_seed

# 2. 手动查看JSON获取te0信息
cat result/ch5/exp5_3_seed/suspected_gpa_range_53.json | jq '{te0_symbol_vma, te0_inpage_offset}'

# 3. 手动构造cmdline
sudo -E python3 src/scripts/run_53.py \
    --suspected-range-json result/ch5/exp5_3_seed/suspected_gpa_range_53.json \
    --guest-extra-cmdline "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60" \
    --discover-only
```

### 现在（自动）

```bash
# 1. 运行seed
sudo -E python3 src/scripts/run_53_seed_range.py \
    --outdir result/ch5/exp5_3_seed

# 2. 直接使用JSON，无需手动指定cmdline
sudo -E python3 src/scripts/run_53.py \
    --suspected-range-json result/ch5/exp5_3_seed/suspected_gpa_range_53.json \
    --discover-only

# guest_extra_cmdline会自动生成！
```

---

## 验证

### 方法1: 使用测试脚本

```bash
./test_auto_cmdline.sh
```

### 方法2: 手动验证

```bash
# 1. 检查seed生成的JSON
cat result/ch5/exp5_3_seed/suspected_gpa_range_53.json | jq '.guest_cmdline_extra'

# 期望输出:
# "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60"

# 2. 运行discover-only
sudo -E python3 src/scripts/run_53.py \
    --suspected-range-json result/ch5/exp5_3_seed/suspected_gpa_range_53.json \
    --discover-only \
    --outdir result/ch5/test_auto

# 3. 检查生成的meta
cat result/ch5/test_auto/meta_53.json | jq '.guest_cmdline_extra'

# 期望输出:
# "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60"
```

---

## 工作流程

```
1. Seed阶段
   ├─ 读取guest_victim_aes符号表
   ├─ 获取te0_symbol_vma和te0_file_offset
   ├─ 计算te0_inpage_offset
   ├─ 生成完整的guest_cmdline_extra
   └─ 保存到suspected_gpa_range_53.json

2. Discovery/Full实验阶段
   ├─ 读取suspected_gpa_range_53.json
   ├─ 提取te0_symbol_vma和te0_inpage_offset
   ├─ 自动生成guest_cmdline_extra
   │   ├─ nokaslr
   │   ├─ norandmaps
   │   ├─ oracle_te0=1
   │   ├─ oracle_te0_vma=0x...
   │   └─ oracle_te0_off=0x...
   └─ 传递给QEMU启动VM
```

---

## JSON格式

### suspected_gpa_range_53.json

```json
{
  "te0_symbol_vma": "0x409f60",
  "te0_file_offset": "0x9f60",
  "te0_inpage_offset": "0xf60",
  "guest_cmdline_extra": "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60",
  "suspected_scan_start_gpa": "0x...",
  "suspected_scan_end_gpa": "0x...",
  ...
}
```

### meta_53.json（实验输出）

```json
{
  "guest_cmdline_extra": "nokaslr norandmaps oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60",
  "te0_gpa": "0x...",
  ...
}
```

---

## 优势

1. **简化使用**: 不需要手动构造复杂的cmdline
2. **避免错误**: 自动从JSON读取，不会输错参数
3. **一致性**: 确保seed和实验使用相同的te0信息
4. **可追溯**: JSON中保存完整的cmdline，便于复现

---

## 向后兼容

如果用户仍然手动指定`--guest-extra-cmdline`，会怎样？

```bash
sudo -E python3 src/scripts/run_53.py \
    --suspected-range-json result/ch5/exp5_3_seed/suspected_gpa_range_53.json \
    --guest-extra-cmdline "nokaslr norandmaps custom_param=1" \
    --discover-only
```

**行为**:
1. 保留用户指定的参数（`nokaslr norandmaps custom_param=1`）
2. 移除旧的oracle参数（如果有）
3. 添加新的oracle参数（从JSON读取）
4. 最终cmdline: `nokaslr norandmaps custom_param=1 oracle_te0=1 oracle_te0_vma=0x409f60 oracle_te0_off=0xf60`

**结论**: 用户可以添加自定义参数，oracle参数会自动更新。

---

## 故障排除

### 问题1: Oracle参数未生成

**症状**:
```bash
cat meta_53.json | jq '.guest_cmdline_extra'
# 输出: "nokaslr norandmaps"  # 缺少oracle参数
```

**原因**:
- `suspected_gpa_range_53.json`中缺少`te0_symbol_vma`或`te0_inpage_offset`

**解决**:
```bash
# 检查JSON
cat suspected_gpa_range_53.json | jq '{te0_symbol_vma, te0_inpage_offset}'

# 如果缺失，重新运行seed
sudo -E python3 src/scripts/run_53_seed_range.py
```

### 问题2: Oracle参数错误

**症状**:
```bash
grep "victim_aes_oracle" vm_attack/qemu_console.log
# 输出: te0_gpa=0x101c5ef60  # 与JSON中的不一致
```

**原因**:
- Seed使用的binary与实验使用的binary不同
- Te0符号地址变化

**解决**:
```bash
# 重新运行seed，确保使用正确的binary
sudo -E python3 src/scripts/run_53_seed_range.py \
    --te0-symbol-bin src/build/guest_victim_aes
```

---

## 总结

**改进前**:
- 需要手动查看JSON
- 需要手动构造cmdline
- 容易出错

**改进后**:
- 只需提供`--suspected-range-json`
- 自动生成完整cmdline
- 简单可靠

**使用建议**:
1. 运行seed生成JSON
2. 直接使用JSON运行实验
3. 不需要手动指定`--guest-extra-cmdline`

---

## 相关文件

- 改进代码: `src/scripts/run_53.py` (line 1720-1771)
- Seed代码: `src/scripts/run_53_seed_range.py` (line 1044-1073)
- 测试脚本: `test_auto_cmdline.sh`
