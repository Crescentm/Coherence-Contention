# 5.3 实验全流程记录（端到端 AES T-Table 密钥恢复）

## 1. 文档目的

这份文档汇总第 5.3 实验从最初搭建到当前状态的完整过程，覆盖：

- 实验目标与约束
- 实际执行流程（seed → discovery → line scan → recovery）
- 每轮实验结果
- 调试问题、根因与修复
- 已落地优化与下一轮建议

本文档是“过程记录”，不是单次 run 的快照。

---

## 2. 实验目标与约束（按 `require/ch5.md`）

核心目标是实现 **service-only** 的端到端攻击流程：

1. 受害者 VM 仅提供 AES/RSA 服务接口（TCP 9000/9001）。
2. Guest 不自报 Te0–Te3 的 VA/GPA。
3. 宿主通过 NPT Accessed 位差分 + 相干信号确认目标页。
4. 完成 `seed 范围定位 -> 页面确认 -> 64 行选线 -> 单字节/全密钥恢复 -> 收敛曲线`。

关键约束：

- `te0_inpage_offset` 允许离线从同版本 ELF 提取（ASLR 无关），但运行时 GPA 必须通过宿主侧机制确认。
- 依赖 KVM 扩展能力：`NPT_CLEAR_ACCESSED` / `NPT_SCAN_ACCESSED`。

---

## 3. 代码与产物入口

主要脚本：

- `<COHERE_REPO>/src/scripts/run_53_seed_range.py`
- `<COHERE_REPO>/src/scripts/run_53.py`

本次整理涉及的主要结果目录：

- `<COHERE_REPO>/result/ch5/exp5_3_seed_20260329_173237`
- `<COHERE_REPO>/result/ch5/exp5_3_seed_20260329_173548`
- `<COHERE_REPO>/result/ch5/exp5_3_seed_20260329_173731`
- `<COHERE_REPO>/result/ch5/exp5_3_20260329_174055`
- `<COHERE_REPO>/result/ch5/exp5_3_20260329_174650`

---

## 4. 标准实验流程（当前实现）

### 4.1 Seed 阶段（候选 GPA 范围）

脚本：`run_53_seed_range.py`

- 启动 victim-services VM
- 宿主通过 NPT Accessed 位做触发/基线差分
- 聚类得到候选页簇并扩展 `pad_pages`
- 输出 `suspected_gpa_range_53.json`

典型命令：

```bash
sudo -E python3 src/scripts/run_53_seed_range.py \
  --mem 4G \
  --discover-rounds 12 \
  --trigger-requests-per-round 16 \
  --pad-pages 2
```

### 4.2 Discovery 阶段（确认目标页）

脚本：`run_53.py --discover-only`

- 对 seed 给出的候选范围再次做 NPT 差分
- 对 Top 候选页做 coherence score 验证
- 输出 `selected_target_page.json`

### 4.3 Full 阶段（选线 + 恢复 + 收敛）

脚本：`run_53.py`

- line scan 生成 `line_snr_53.csv`、`topk_lines_53.json`
- key recovery 生成 `single_byte_scores`、`full_key_scores`、`convergence_53.csv`
- 汇总到 `recovery_summary_53.json` 和 `stats_53.txt`

---

## 5. 调试过程与问题闭环

以下是 5.3 实施过程中出现过的关键问题与修复结果。

### 5.1 QEMU 启动路径错误（plain QEMU / BIOS 报错）

现象：

- `qemu: could not load PC BIOS 'bios-256k.bin'`
- 实际走了 plain QEMU 路径，未走 AMDSEV 定制构建

根因：

- 脚本路径解析不稳定，未强制 AMDSEV QEMU + OVMF。

修复：

- 脚本固定优先使用：
  - `<COHERE_REPO>/AMDSEV/qemu/build/qemu-system-x86_64`
  - `<COHERE_REPO>/AMDSEV/ovmf/Build/OvmfX64/DEBUG_GCC5/FV/OVMF.fd`

状态：已修复。

### 5.2 VM fd 获取失败（`ENXIO`）

现象：

- `cannot acquire kvm-vm fd in pid=...: [Errno 6] No such device or address`

根因：

- 通过 `/proc/<pid>/fd/*` 直接在宿主脚本进程跨进程复用 VM fd，不稳定。

修复：

- 引入 preload `nptctl` 模式，在 QEMU 进程内持有 VM fd。
- 宿主脚本通过 Unix socket RPC（`NPT_CLEAR/NPT_SCAN/GPA_TO_HPA/READ_GPA`）调用。

状态：已修复。

### 5.3 服务就绪超时（`victim services not ready`）

现象：

- VM 已起，但脚本判定服务端口未就绪。

根因：

- 早期 `ip=dhcp` 在 user-net 路径下波动较大。

修复：

- 改为固定内核参数：
  - `ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off`

状态：已修复。

### 5.4 NPT ioctl `EIO`

现象：

- `OSError: [Errno 5] Input/output error`（clear/scan 阶段）

根因：

- 早期控制路径和 VM 进程生命周期不同步，ioctl 执行上下文不一致。

修复：

- 与 5.2 同步解决：统一切换到 QEMU 内部 `nptctl` RPC 控制面。

状态：已修复。

### 5.5 `taskset` 与 `LD_PRELOAD` 组合冲突

现象：

- 部分 run 在注入和绑核组合下行为异常。

修复：

- 去掉外层 `taskset` 包裹。
- 改为 `preexec_fn + sched_setaffinity()` 设置 CPU 亲和性。

状态：已修复。

### 5.6 discover-only 空结果

现象：

- `exp5_3_20260329_174055` 出现：
  - `npt_page_ranking.csv` 只有表头，空结果。

根因：

- 使用 seed 的窄范围再次发现时，时间窗口和页簇波动导致“空命中”。

修复：

- `run_53.py` 增加 fallback：若 seed 范围 discovery 为空，则自动回退全内存范围扫描（`0..mem`）。

状态：已修复（`exp5_3_20260329_174650` 已触发回退并完成全流程）。

---

## 6. 已执行实验结果汇总

### 6.1 Seed 阶段（3 次独立）

数据来源：

- `.../stats_seed_53.txt`
- `.../suspected_gpa_range_53.json`

共同结果：

- `te0_symbol_vma = 0x408de0`
- `te0_file_offset = 0x8de0`
- `te0_inpage_offset = 0xde0`
- `cluster_pages = 33`
- `discover_rounds = 12`
- `trigger_requests_per_round = 16`

三次范围（均为 33 页簇 + 两侧 pad 2 页）：

1. `exp5_3_seed_20260329_173237`
   - `suspected_scan_start_gpa=0x66f7a000`
   - `suspected_scan_end_gpa=0x66fa2000`
2. `exp5_3_seed_20260329_173548`
   - `suspected_scan_start_gpa=0x72b7a000`
   - `suspected_scan_end_gpa=0x72ba2000`
3. `exp5_3_seed_20260329_173731`
   - `suspected_scan_start_gpa=0x38d7a000`
   - `suspected_scan_end_gpa=0x38da2000`

观察：

- 三次 seed 结构非常一致，说明“服务触发 + NPT 差分 + 聚类”流程可复现性较好。

### 6.2 主流程 run #1：`exp5_3_20260329_174055`

结果：

- discovery 空结果。
- 无 `metrics_53.json` 产出。

证据：

- `discovery/npt_page_ranking.csv` 仅表头。

结论：

- 该 run 作为“窄范围 discovery 不稳定”的反例，推动了 fallback 全内存扫描机制。

### 6.3 主流程 run #2：`exp5_3_20260329_174650`（完整跑通）

关键文件：

- `meta_53.json`
- `line_scan/line_snr_53.csv`
- `key_recovery/recovery_summary_53.json`
- `stats_53.txt`

核心结果：

- 目标页：`te_page_gpa=0x19e08000`
- `te0_gpa=0x19e08de0`（页内偏移 `0xde0`）
- `te_total_lines=65`（跨页情况）
- `best_k=top1`
- `best_byte_accuracy=0.0625`（16 字节仅 1 字节正确）
- `best_full_key_success=0`
- PoC：`poc_best_key=0xc0`，错误。
- 收敛曲线平坦：
  - 1000/2000/5000/10000/20000 全部 `byte_accuracy=0.0625`。

---

## 7. 失败分析（基于 174650 实测）

### 7.1 全局 Top-K 选线策略存在结构性偏差

证据：

- `topk_lines_53.json` 中 `top1=[54]`，该行属于 table3。
- 但 `te0_best_line=15` 在 table0。

影响：

- `top1` 仅覆盖 `byte_pos % 4 == 3` 的字节组。
- 其余字节在评分时 `valid_count=0`，导致恢复退化为默认值行为。

佐证（`full_key_scores_top1.csv`）：

- byte 0/1/2/4/5/6/... 等大量字节 `valid_count=0`。

### 7.2 NPT 排名存在大量并列页，页确认压力大

证据：

- `discovery/npt_page_ranking.csv` 前多页均为 `score=12, trigger_hits=12, baseline_hits=0`。

影响：

- 仅靠 NPT score 不足以区分单一目标页，必须依赖后续 coherence 验证（当前已做，但仍有噪声压力）。

### 7.3 观测与判决偏硬，抗噪不足

表现：

- 原策略主要依赖固定阈值和二值命中。
- 面对跨页、跨表和噪声，区分度不足。

---

## 8. 已实施优化（代码已落地）

以下优化已实现于：

- `<COHERE_REPO>/src/scripts/run_53.py`

### 8.1 表感知 Top-K 选线

- 从“全局排序前 K”改为“每个表分别取前 N 再合并”。
- 目前支持：`top1/top2/top3/top4/top5/top8/top64/top_all`。

### 8.2 自适应阈值模式

新增参数：

- `--theta-mode {global,line_mid,line_scaled,line_sigma}`
- `--theta-scale`

说明：

- 支持每条线独立阈值，降低统一阈值带来的偏置。

### 8.3 观测增强与样本过滤

新增参数：

- `--trigger-repeat-per-sample`
- `--min-hit-lines`
- `--max-hit-lines`
- `--sample-max-attempt-factor`

说明：

- 允许每个样本重复触发放大信号。
- 过滤异常样本（命中过少或过多）。

### 8.4 评分增强

新增参数：

- `--score-mode {binary,soft}`
- `--min-valid-per-byte`

说明：

- `soft` 使用阈值以上幅度信息，而不仅是二值 hit。
- `min_valid_per_byte` 防止低覆盖字节把结果拉偏。

### 8.5 可观测性增强

- 输出 `observation_stats`（尝试数、保留数、丢弃数）。
- `meta_53.json` / `stats_53.txt` 记录阈值模式与评分模式配置。

---

## 9. 当前状态结论

### 9.1 已达成

- 5.3 pipeline 已能端到端跑通（含 seed、discovery、line scan、recovery）。
- Guest 不再依赖自报 Te0 VA/GPA。
- NPT Accessed + coherence 双阶段定位链路已经实现并可重复运行。

### 9.2 尚未达成

- 目前尚未得到可用于论文 5.3-C/5.3-D 的“高正确率恢复结果”。
- 现有最佳 run（174650）仅 1/16 字节正确，收敛不成立。

---

## 10. 下一轮实验建议（直接可执行）

建议优先验证新优化后的恢复能力：

```bash
sudo -E python3 src/scripts/run_53.py \
  --suspected-range-json <COHERE_REPO>/result/ch5/exp5_3_seed_20260329_173731/suspected_gpa_range_53.json \
  --theta 466 \
  --theta-mode line_mid \
  --score-mode soft \
  --trigger-repeat-per-sample 2 \
  --line-reps 48 \
  --samples 30000 \
  --min-valid-per-byte 32 \
  --sample-max-attempt-factor 3 \
  --checkpoints 1000,2000,5000,10000,20000,30000
```

若仍不收敛，建议继续：

1. 将 `topk` 进一步改为“按 byte_pos 映射到对应表的专属候选集”。
2. 针对 `te_total_lines=65` 场景单独校验边界行（line 64）对评分的影响。
3. 引入多轮投票式恢复（同配置重复 run，按字节聚合）。

---

## 11. 与论文写作的对应关系

可直接引用到论文 5.3 的材料：

- Seed 稳定性：三次独立 seed 的 33 页一致规模与固定 `te0_inpage_offset=0xde0`。
- Discovery 反例与修复：`174055` 空结果 -> fallback 全内存范围。
- 失败案例分析：`174650` 的覆盖不足与收敛失败。
- 优化方法学：表感知选线、自适应阈值、软评分、样本过滤。

建议写作方式：

- 先报告“原始流程可跑通但恢复失败”的客观事实。
- 再按“根因 -> 对应优化 -> 优化后对比实验”展开，形成严谨叙事闭环。

