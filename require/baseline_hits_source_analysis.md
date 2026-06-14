# Baseline_hits特征来源分析

## Victim程序源码分析

### 程序结构

```c
int main(int argc, char **argv) {
  // 1. 初始化AES key (line 219)
  if (AES_set_encrypt_key(fixed_key, 128, &aes_key) != 0) {
    return 1;
  }

  // 2. 设置监听socket (line 224)
  lfd = setup_listener(port);

  // 3. 打印oracle信息 (line 231)
  maybe_print_te0_gpa_oracle(&cfg);

  // 4. 进入服务循环 (line 236)
  for (;;) {
    int cfd = accept(lfd, NULL, NULL);  // 阻塞等待连接
    if (readn(cfd, plaintext, sizeof(plaintext)) == sizeof(plaintext)) {
      AES_encrypt(plaintext, ciphertext, &aes_key);  // 加密
      writen(cfd, ciphertext, sizeof(ciphertext));
    }
    close(cfd);
  }
}
```

### 关键观察

1. **程序启动后只做一次初始化**
   - `AES_set_encrypt_key()` 只调用一次（line 219）
   - 之后进入无限循环，阻塞在 `accept()` 上

2. **没有周期性操作**
   - 没有定时器
   - 没有后台线程
   - 没有周期性的维护代码

3. **只有在收到连接时才执行AES**
   - `AES_encrypt()` 只在收到请求时调用（line 247）
   - 在baseline阶段（没有发送请求），不应该调用 `AES_encrypt()`

## NPT Discovery时序分析

### Discovery流程

```python
for r in range(100):  # 100轮discovery
    # 1. 清除NPT A/D bits
    npt.npt_clear(...)

    # 2. Baseline阶段：等待5ms
    time.sleep(0.005)

    # 3. 扫描baseline访问
    base = npt.npt_scan(...)
    base_pages = set(...)

    # 4. 清除NPT A/D bits
    npt.npt_clear(...)

    # 5. Trigger阶段：发送50个AES请求
    for _ in range(50):
        aes_request(...)

    # 6. 扫描trigger访问
    trig = npt.npt_scan(...)
    trig_pages = set(...)

    # 7. 累积统计
    for p in base_pages:
        base_hits[p] = base_hits.get(p, 0) + 1
    for p in trig_pages:
        trig_hits[p] = trig_hits.get(p, 0) + 1
```

### Baseline阶段的5ms内发生了什么？

在这5ms内：
- Victim程序阻塞在 `accept()` 上，等待连接
- **没有发送任何AES请求**
- 理论上不应该访问Te0表

但是实验观察到：
- Te0的所有页面在某些轮次的baseline阶段被访问
- Baseline_hits = 1或3（不同实验不同）

## 可能的解释

### 假设1：OpenSSL的延迟初始化

**可能性：低**

`AES_set_encrypt_key()` 在程序启动时就调用了，不是延迟初始化。

### 假设2：Guest VM的后台活动

**可能性：中**

Guest VM可能有：
- 内核调度器
- 中断处理
- 页面回收
- TLB刷新

这些活动可能偶然访问Te0页面。

### 假设3：NPT A/D bits的累积效应

**可能性：高**

**关键发现：** NPT A/D bits的清除可能不是瞬时的！

```python
# Round 0
clear1()  # 清除A/D bits
sleep(5ms)  # Baseline阶段
base_scan()  # 扫描 - 可能看到之前的访问？

# 如果clear1()之前有访问Te0（例如程序启动时的AES_set_encrypt_key）
# 那么这些访问可能在第一轮的baseline阶段被观察到
```

**验证：**
- 如果baseline_hits=1，说明只在第一轮被观察到
- 如果baseline_hits=3，说明在前3轮被观察到
- 这取决于NPT clear的时序和TLB刷新的延迟

### 假设4：程序启动时的初始化访问

**可能性：最高**

**时序分析：**

```
T0: 程序启动
T1: AES_set_encrypt_key() 调用 - 可能访问Te0表
T2: setup_listener()
T3: maybe_print_te0_gpa_oracle()
T4: 进入accept()循环
T5: NPT discovery开始
T6: Round 0 - clear1()
T7: Round 0 - baseline阶段（5ms）
T8: Round 0 - base_scan() - 观察到T1的访问？
```

**关键问题：** T1的访问是否会在T8被观察到？

这取决于：
1. NPT A/D bits何时被设置（T1时）
2. NPT clear何时生效（T6时）
3. 是否有延迟或缓存效应

## OpenSSL AES_set_encrypt_key分析

### 可能的实现

OpenSSL的 `AES_set_encrypt_key()` 可能：

1. **生成轮密钥**
   - 从原始密钥扩展出10轮的轮密钥
   - 存储在 `AES_KEY` 结构体中（栈上）

2. **访问Te0表？**
   - 如果使用table-based实现，可能会访问Te0
   - 如果使用AES-NI硬件加速，不会访问Te0

3. **预热缓存？**
   - 可能会预加载Te0表到缓存
   - 这会触发NPT page fault

## 结论

### Baseline_hits的来源

**最可能：** 程序启动时 `AES_set_encrypt_key()` 的初始化访问

**证据：**
1. Victim程序只在启动时调用一次 `AES_set_encrypt_key()`
2. Baseline_hits=1或3，说明只在前几轮被观察到
3. 之后的轮次不再有baseline访问

**机制：**
- `AES_set_encrypt_key()` 访问Te0表（可能是预热缓存或验证）
- 这个访问设置了NPT A/D bits
- 第一轮（或前几轮）的baseline scan观察到这个访问
- 之后的轮次，NPT clear清除了这些bits

### 这是OpenSSL特定的还是Victim特定的？

**答案：OpenSSL特定的**

**原因：**
1. Victim程序本身没有任何特殊的代码
2. 只是简单地调用 `AES_set_encrypt_key()` 和 `AES_encrypt()`
3. Baseline访问的行为取决于OpenSSL的实现

**通用性：**
- ✓ 对于使用OpenSSL table-based AES的程序，应该通用
- ✗ 对于使用AES-NI硬件加速的程序，可能不work
- ✗ 对于使用其他加密库的程序，可能不work

### Baseline_hits值的变化

**为什么有时是1，有时是3？**

可能的原因：
1. **NPT clear的时序**
   - 不同实验中，discovery开始的时间不同
   - 相对于程序启动的延迟不同

2. **TLB刷新的延迟**
   - NPT clear包含TLB flush
   - TLB flush可能有延迟或不完全

3. **Guest VM的调度**
   - 不同的调度可能导致不同的访问模式

## 建议

### 1. 使用Baseline_consistent而不是Baseline_is_1

**原因：**
- Baseline_hits的具体值不稳定（1或3）
- 但所有Te0页面的值总是相同的（一致性）
- Baseline_consistent是更鲁棒的特征

### 2. 测试通用性

建议测试：
- 不同的OpenSSL版本
- 不同的AES实现（AES-NI vs table-based）
- 不同的加密库（libgcrypt, mbedtls）

### 3. 理解限制

这个特征依赖于：
- OpenSSL的table-based AES实现
- `AES_set_encrypt_key()` 的初始化行为
- NPT A/D bits的时序特性

如果目标程序不满足这些条件，特征可能失效。

## 验证实验

### 建议的验证方法

1. **修改victim程序**
   ```c
   // 在discovery开始前，多次调用AES_set_encrypt_key
   for (int i = 0; i < 10; i++) {
       AES_set_encrypt_key(fixed_key, 128, &aes_key);
   }
   ```
   预期：baseline_hits会增加

2. **延迟discovery开始**
   ```python
   # 在discovery开始前等待更长时间
   time.sleep(10)  # 等待10秒
   # 然后开始discovery
   ```
   预期：baseline_hits可能变为0（初始化访问已经被清除）

3. **使用AES-NI**
   ```bash
   # 编译OpenSSL时启用AES-NI
   # 或者在CPU中启用AES-NI指令
   ```
   预期：baseline_hits可能变为0（不访问Te0表）
