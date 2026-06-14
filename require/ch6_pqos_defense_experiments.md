# 第 6 章防御实验说明

本文档整理第 6 章中已经完成并获得有效结果的两组防御实验：

- 基于 `resctrl` 的 LLC 分区实验
- 基于 `resctrl` 的 MBA 带宽限制实验

当前文档只记录已经能够稳定运行并得到可解释结果的部分，不包含尚未完成端到端验证的私有页 UC 实验。

## 1. 实验目的

第 6 章提出的宿主侧防御方案包含三层机制：

1. 利用 PQoS/`resctrl` 将机密虚拟机与宿主机 VMM 放入不同 LLC 路集合
2. 将私有页设置为 UC，以削弱宿主侧可缓存副本
3. 对宿主机 VMM 所属 CLOSID 施加较低的内存带宽上限，以削弱基于 NOCACHE 的物理内存竞争信号

目前已经完成验证的是第 1 层和第 3 层。对应实验目标分别为：

- 验证 LLC 分区是否能够显著压低基于 `CACHEABLE` 探测的 coherence 信号
- 验证 MBA 带宽限制是否能够显著压低基于 `NOCACHE` 探测的 contention 信号

## 2. 实验原理

### 2.1 LLC 分区实验原理

宿主线程与机密虚拟机 vCPU 若共享 LLC 路集合，则宿主侧 `CACHEABLE` 探测更容易观察到来宾访存触发的缓存层次效应。在启用 `resctrl` 后，实验将 LLC 的 way mask 分成两组：

- 宿主组使用低半部分路集合
- CVM 组使用高半部分路集合

这样，宿主线程与来宾线程在 LLC 中不再竞争同一组 cache way。若 coherence 信号主要依赖这类共享缓存结构，则启用分区后，A/B 两组样本的延迟差异应明显减小。

### 2.2 MBA 带宽限制实验原理

contention 信号的核心在于宿主机通过 `NOCACHE` 突发探测连续访问目标物理页，并在短窗口内观察竞争引起的延迟差异。若通过 `resctrl` 对宿主组施加较低的内存带宽上限，则宿主机在单位时间内可发起的有效探测会减少。结果上表现为：

- 有效 burst 强度下降
- A/B 两组在探测窗口中的竞争差异减弱
- 延迟分布趋于重合

因此，MBA 实验关注的是内存竞争信号的衰减，而不是缓存层内的共享关系。

## 3. 实验实现

### 3.1 使用的程序

当前实验使用的主脚本和相关实现如下：

- `src/scripts/run_aes_toggle.py`
- `src/scripts/ch6_resctrl.py`
- `src/host_runner_modes/mode_aes_toggle.c`

其中：

- `run_aes_toggle.py` 负责启动来宾、配置宿主测量模式并汇总结果
- `ch6_resctrl.py` 负责对 `/sys/fs/resctrl` 做分组、写入 `schemata` 和分配线程
- `mode_aes_toggle.c` 为宿主预加载测量线程，负责在每次 guest AES 调用后立即探测目标缓存行

### 3.2 来宾行为

来宾程序为 `guest_aes_toggle`。它反复交替触发两类 AES 输入：

- Group A：访问 `T0[0..7]`
- Group B：访问 `T0[128..255]`

两组输入访问 `Te0` 中不同位置，对应不同的宿主侧观测模式。宿主线程在每次 AES 调用后立即探测目标缓存行，并记录：

- 当前样本属于 A 组还是 B 组
- 对应的 `tsc_delta`

若信号存在，则两组样本的延迟分布应出现可分离差异。若防御有效，则这种差异应显著缩小甚至消失。

### 3.3 宿主线程分组方式

在启用 `resctrl` 时，脚本会：

1. 读取 `/sys/fs/resctrl/info/L3/cbm_mask`
2. 将可用 mask 等分为两组
3. 创建：
   - `*_host`
   - `*_cvm`
   两个控制组
4. 将：
   - QEMU 的 vCPU 线程分配到 `cvm` 组
   - 宿主攻击线程及其余宿主线程分配到 `host` 组

这样可以在同一实验框架下直接比较：

- 不启用分区
- 启用 LLC 分区
- 启用 MBA 限速

## 4. LLC 分区实验

### 4.1 实验命令

本实验使用命令：

```bash
sudo -E python3 <COHERE_REPO>/src/scripts/run_aes_toggle.py \
  --iters 1500 \
  --probe-mode cacheable \
  --probe-burst 1 \
  --resctrl-enable \
  --resctrl-prefix ch6_coh_pqos \
  --outdir <COHERE_REPO>/result/ch6/ch6_coh_pqos
```

### 4.2 分区配置

实验结果目录：

- `result/ch6/ch6_coh_pqos`

其中 [`resctrl_assignment.json`](<COHERE_REPO>/result/ch6/ch6_coh_pqos/vm/resctrl_assignment.json) 显示：

- `cbm_mask_hex = 0xffff`
- `host_mask_hex = 0xff`
- `cvm_mask_hex = 0xff00`

说明宿主组和 CVM 组已经被分配到互不重叠的 LLC 路集合中。

### 4.3 信号结果

分析结果见：

- [`aes_toggle_analysis.json`](<COHERE_REPO>/result/ch6/ch6_coh_pqos/aes_toggle_analysis.json)

主要指标为：

- `median_a = 711`
- `median_b = 711`
- `mean_a = 730.46`
- `mean_b = 738.37`
- `separation_median = 0`
- `snr = 0`

### 4.4 结果解释

在启用 LLC 分区后，A/B 两组样本的中位数完全重合，信号分离降为 0，`SNR` 也降为 0。这说明在当前 `CACHEABLE` 探测模式下，原本依赖 LLC 共享关系的可分离差异已基本消失。

从实验目的出发，这一结果支持以下判断：

- 基于 `resctrl` 的 LLC 分区可以有效抑制当前 coherence 测量链路中的信号

## 5. MBA 带宽限制实验

### 5.1 实验命令

本实验使用命令：

```bash
sudo -E python3 <COHERE_REPO>/src/scripts/run_aes_toggle.py \
  --iters 1500 \
  --probe-mode nocache \
  --probe-burst 16 \
  --resctrl-enable \
  --resctrl-prefix ch6_cnt_mba \
  --resctrl-host-mba 20 \
  --outdir <COHERE_REPO>/result/ch6/ch6_cnt_mba
```

### 5.2 分组与带宽限制配置

实验结果目录：

- `result/ch6/ch6_cnt_mba`

其中 [`resctrl_assignment.json`](<COHERE_REPO>/result/ch6/ch6_cnt_mba/vm/resctrl_assignment.json) 显示：

- `host_mask_hex = 0xff`
- `cvm_mask_hex = 0xff00`
- `host_mba_percent = 20`

说明宿主组不仅与 CVM 分离了 LLC way，还额外施加了 20% 的 MBA 限速。

### 5.3 信号结果

分析结果见：

- [`aes_toggle_analysis.json`](<COHERE_REPO>/result/ch6/ch6_cnt_mba/aes_toggle_analysis.json)

主要指标为：

- `median_a = 548.5`
- `median_b = 549.0`
- `mean_a = 566.56`
- `mean_b = 566.33`
- `separation_median = -0.5`
- `snr = 0.0084`

### 5.4 结果解释

在 `NOCACHE` 突发探测模式下，如果宿主侧仍能在短窗口内高频发起访问，则 A/B 两组通常会表现出不同的竞争延迟分布。当前实验在宿主组施加 MBA 限速后，两组样本的中位数差仅为 `0.5` cycles，`SNR` 降至 `0.0084`，说明在当前测量窗口中已经难以利用该信号区分两类访问模式。

从实验目的出发，这一结果支持以下判断：

- 基于 `resctrl` 的 MBA 限速能够有效削弱当前的物理内存竞争信号

## 6. 实验结论

当前已经完成的两组防御实验可以得到以下结论。

1. **LLC 分区对 coherence 信号有效。**  
   在 `CACHEABLE` 探测模式下，启用 LLC 分区后，A/B 两组样本的中位数分离降为 0，说明该信号已被显著压制。

2. **MBA 限速对 contention 信号有效。**  
   在 `NOCACHE` 突发探测模式下，宿主组施加 20% MBA 限速后，A/B 两组样本的中位数差收敛到 `0.5` cycles，`SNR` 仅为 `0.0084`，说明竞争信号已被显著削弱。

3. **两种机制作用于不同层次。**  
   LLC 分区主要削弱共享缓存路径上的可观测差异，MBA 限速主要削弱 NOCACHE 竞争探测的有效采样能力。两者并不是同一种防御，而是分别对应第 6 章所述防御体系中的不同层次。

## 7. 当前未纳入结论的部分

虽然代码中已经补入了基于现有 `KVM_SET_MEMORY_ATTRIBUTES` 的宿主页属性控制接口，但“私有页 UC”对应的端到端实验链路尚未完全理顺，因此当前不将其纳入最终实验结论。

更具体地说：

- 当前 `ch6_host_uc` 结果改变了延迟分布
- 但尚未能证明 coherence 信号被稳定消除

因此，第 6 章当前建议只将：

- LLC 分区实验
- MBA 带宽限制实验

作为已完成的防御验证结果写入论文。
