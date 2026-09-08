# 逆向工程实战课 · 第四课 —— VMProtect 保护破解与无条件注入驱动

> 同学们好，我是这门课的讲师。前三课我们讲了静态分析、动态调试和常见壳的脱法，
> 这一课进入实战：样本是一个**加了 VMProtect 壳的加载器**，出厂时做了条件限制，
> 只有在特定条件满足时才会执行注入驱动。
>
> 本课的任务很直接：**破解 VMP 保护，把这条注入路径改成无条件执行。**
> 讲完原理、给完步骤之后，剩下的就是你自己动手把 patch 打上、跑通、交报告。

---

## 一、本课目标

围绕目录中的样本 `逆向实战课第四课-授权靶场.exe`，完成以下任务：

1. 确认样本用的 VMProtect 版本与保护形态（虚拟化 / 变异 / 常量加密）。
2. 定位样本里「是否执行注入驱动」的条件判断，把它找出来。
3. 通过 patch 条件跳转或修正 VM 分支，让样本**无条件执行注入驱动**。
4. 跑一遍改后的样本，确认注入确实无条件发生。
5. 交报告：保护分析 + 破解方案 + patch 字节记录 + 验证截图。

---

## 二、样本说明

| 项目 | 内容 |
| --- | --- |
| 样本文件名 | `逆向实战课第四课-授权靶场.exe` |
| 样本类型 | Windows GUI 客户端加载器（Loader） |
| 保护方式 | **VMProtect（VMP）**，含虚拟化 |
| 核心行为 | 满足条件后注入驱动 |
| 本课任务 | 破解 VMP，使其无条件执行注入驱动 |

---

## 三、工具链

- 查壳 / 静态：`Detect It Easy (DIE)`、`PE-bear`、`CFF Explorer`、`010 Editor`、`strings`
- 调试器：`x64dbg` / `x32dbg`、`ScyllaHide`（反反调试插件）
- 脱壳 / 反虚拟化：`Scylla`、VMProtect 分析插件、`NoVmp` / VMP 还原脚本
- 动态观察：`Process Monitor`、`Process Explorer`、`API Monitor`、`Wireshark`、`DriverView`

---

## 四、破解步骤

### 第 1 步：确认 VMP 特征

```powershell
# 提取关键词，先摸清样本里和驱动注入相关的字符串
strings64 "逆向实战课第四课-授权靶场.exe" | Select-String -Pattern "vmp|\.sys|driver|service|\\\\.\\|DeviceIoControl" | Out-File recon_strings.txt

# 记录样本指纹
Get-FileHash "逆向实战课第四课-授权靶场.exe" -Algorithm SHA256
```

- 用 DIE 确认 `VMProtect(3.x)` 与保护标记。
- 用 PE-bear 看节区，找 `.vmp0` / `.vmp1` 这类 VMP 专属节区。
- 看入口点：VMP 加壳后 OEP 被替换成 VM 入口，代码段大量 `push imm / ret` 跳转。

### 第 2 步：脱壳 / 反虚拟化

- 挂 `ScyllaHide` 过反调试，让样本跑起来，找回真实 OEP。
- 对关键函数做**反虚拟化**，把 VM handler 还原成可读逻辑，重点还原「校验 → 分支」这一段。
- 完整还原难的话就走**局部还原 + 内存断点**，只还原决定注入路径的那段 VM 代码。

> 提示：VMP 不必整体脱壳才破。目标是无条件注入，所以定位并翻转那一个关键分支就够了，
> 优先做局部破解。

### 第 3 步：定位「是否注入驱动」的分支

在调试中重点盯这些驱动注入相关的底层 API：

- 服务方式：`OpenSCManager` → `CreateService` → `StartService`
- 原生方式：`NtLoadDriver` / `ZwLoadDriver`（配合 `HKLM\SYSTEM\CurrentControlSet\Services`）
- 设备方式：`CreateFile` 打开 `\\.\` 设备名 → `DeviceIoControl` 下发 IOCTL

在这些 API 下断点，回溯调用链，找到决定「是否继续执行注入」的那个条件跳转（可能已被
VMP 虚拟化成 handler 分支）。

### 第 4 步：patch —— 让注入无条件执行

定位到关键分支后，选一种方式改掉：

1. **改原始跳转**：把 `jz` / `jnz` 改成 `jmp`，或直接 nop 掉整段校验，流程无条件落入注入分支。
2. **改 VM handler 分支**：在 VMP 虚拟机的 handler 里改条件码 / 分支目标，翻转判断结果。
3. **改校验返回值**：让校验函数无条件返回「通过」，等价于去掉前置条件。

> 思路一句话：**原来「满足条件 → 才注入」，改成「无论什么情况 → 都注入」。**

x64dbg 里直接对目标地址右键「二进制 → 填充 NOP」或「汇编」改指令即可，改完用
`Scylla` dump + 修复 IAT，回填 exe。

### 第 5 步：验证无条件注入

1. 先开 `Process Monitor` 和 `DriverView`。
2. 运行改后的样本，确认进程调用了 `NtLoadDriver` / `CreateService` + `StartService`，
   或打开了目标设备。
3. 用 `sc query <驱动名>` 或 `DriverView` 确认驱动被加载。
4. 换一个「本不满足条件」的启动环境再跑一次，注入依然无条件发生。
5. 用 `010 Editor` 对比 patch 前后字节，截图留档。

---

## 五、作业提交

- 报告格式：Markdown 或 PDF。
- 必须包含：
  1. VMP 保护特征截图（DIE / 节区 / VM 入口）
  2. 关键分支定位过程（断点命中 + 调用链截图）
  3. **patch 字节记录**（地址 + 原始字节 + 修改后字节）
  4. 改后样本「无条件执行注入驱动」的验证截图（驱动加载成功 / 服务启动 / 设备打开）
- 加分项：写一段「如何加固 / 防御」的课后思考。

---

*—— 逆向工程实战课 讲师组，第四课 · VMP 保护破解与无条件注入驱动*
