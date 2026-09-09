# Loader_PG.exe 逆向分析

本仓库保存一个 Windows 加载器样本（`逆向实战课第四课-授权靶场.exe`，原始文件 `Loader_PG.exe`）
及对其进行的**静态逆向分析记录**。分析工具为 radare2（`rabin2`）与 GNU `strings`，纯静态取证，未运行样本。

---

## 文件指纹

| 项 | 值 |
| --- | --- |
| 样本文件 | `逆向实战课第四课-授权靶场.exe` |
| 大小 | 23,013,888 字节（21.95 MB） |
| SHA256 | `8BFA298B536CB956DE8466A7950D05C7458E8A52D6551C753D0DB357150426E1` |
| 架构 | x86-64（AMD64），PE32+ |
| 子系统 | Windows CUI（控制台） |
| 编译器 | MSVC；`compiled` 时间戳 2025-04-30 17:47:19 UTC |
| 签名 | 无 |

---

## 一、节区结构（VMProtect 打包特征）

| nth | name | vaddr | vsize | perm | raw（文件内） |
| --- | --- | --- | --- | --- | --- |
| 0 | `.text` | 0x140001000 | 0x116000 | -r-x | 0（纯虚拟） |
| 1 | `.rdata` | 0x140117000 | 0x4e000 | -r-- | 0（纯虚拟） |
| 2 | `.data` | 0x140165000 | 0x9000 | -rw- | 0（纯虚拟） |
| 3 | `.pdata` | 0x14016e000 | 0xd000 | -r-- | 0（纯虚拟） |
| 5 | `..\i` | 0x14017c000 | 0xef1000 | -r-x | 0（15.6 MB 可执行） |
| 6 | `.f(` | 0x14106d000 | 0x1000 | -rw- | 0x400 |
| 7 | `.BKh` | 0x14106e000 | 0x15f2000 | -r-x | 0x1200（≈22 MB 可执行） |
| 9 | `.rsrc` | 0x142661000 | 0x1000 | -r-- | 仅 512 字节 |

- `.text` / `.rdata` / `.data` / `.pdata` 在文件里无原始数据（`paddr=0, size=0`），运行时由壳展开。
- 真实载荷集中在一个巨大的可执行节 `.BKh`（flags `0x68000060` = 可执行 + 可读 + 非分页代码）。
- 节名 `..\i` / `.f(` / `.BKh` 为壳重命名产物 → **VMProtect 典型布局**。

---

## 二、导入表（被大幅削减）

可见导入仅约 15 个启动桩：

- **KERNEL32**：`TryAcquireSRWLockExclusive`、`GetSystemTimeAsFileTime`、`HeapAlloc`、
  `HeapFree`、`ExitProcess`、`LoadLibraryA`、`GetModuleHandleA`、`GetProcAddress`
- **CRYPT32**：`CertGetNameStringW`
- **WS2_32**：`getpeername`
- **bcrypt**：`BCryptGenRandom`
- **ADVAPI32**：`CryptGenRandom`
- **SHELL32**：`ShellExecuteA`
- **ole32 / OLEAUT32**：`CoCreateInstance`、`SysStringLen`

关键结论：`OpenSCManager` / `CreateService` / `DeleteService` / `StartService` /
`DeviceIoControl` / `CreateFile` / `NtLoadDriver` 等**均不在导入表**，运行时经
`LoadLibraryA + GetProcAddress` 动态解析——SCM 链、驱动加载、通信口操作全部被隐藏。

---

## 三、字符串（整体加密，局部泄露）

- 全文件仅 **4 条可读字符串**（正常程序数百上千条）→ 字符串被壳整体加密。
- 无明文 URL / 域名 / IP / `.cache` / `.sys` / C2 配置。
- 原始字节中泄露游戏选项片段：`DMZ`、`BO6`（Black Ops 6）。
- `Can't create kernel communication` 等提示串在静态层不可见（加密）。

---

## 四、资源与驱动

- `.rsrc` 仅 512 字节，无有效资源目录 → **驱动（如 `pg39212.sys`）未内嵌**。
- 推断：驱动与 `.cache` 正常路径下由网络（C2）下发，或运行时解密/生成落地，静态文件本身不携带。

---

## 五、结论

该样本为 **VMProtect 高强度打包**：单一大可执行节 + 虚拟节区展开 + 导入削减 +
字符串加密 + 节名混淆，静态层能确定的只有壳结构与少量泄露片段。

要还原 SCM 链、`.cache` 解密逻辑、`\\.\KernelX` 通信口创建，需继续**动态分析**：

- 挂 `ScyllaHide` / Frida 运行，`GetProcAddress` / `LoadLibraryA` 下断，抓运行时解析的 API 名；
- Dump 进程内存，找回解密字符串与 IAT；
- 跟踪 SCM 调用序列与驱动落地路径。

---

## 附：取证命令

```powershell
$f = '.\逆向实战课第四课-授权靶场.exe'
rabin2 -I $f   # 基本信息
rabin2 -S $f   # 节区
rabin2 -i $f   # 导入表
rabin2 -E $f   # 导出表（空）
rabin2 -z $f   # 字符串节（仅 4 条）
strings -n 5 $f # 原始字符串（加密，几乎无明文）
```
