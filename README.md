# AegisNT

[中文](README.md) | [English](README_EN.md)

AegisNT 是一个面向 Windows x64 的系统检查、进程管理和内核调试工具。主程序使用 C++20、Qt 6 和 QFluent 构建，并通过 `Ring0Core.sys` 提供的 `AegisCore` 与 `AegisSentinel` 设备通道扩展用户态 API 无法完成的查询、保护和操作能力。

> 本项目包含进程终止、句柄关闭、内存读写、驱动加载、DLL 注入和安全策略修改等高权限功能。请仅在自己拥有或明确获准测试的设备上使用。错误使用可能导致应用崩溃、系统不稳定或蓝屏。

## 功能概览

- **系统与任务管理**：查看进程、线程、令牌、模块、内存、PEB、句柄及缓解策略，支持实时刷新和详细检查。
- **进程操作**：终止、挂起、恢复、设置 PPL/关键进程状态、令牌操作、DLL 注入及进程保护。
- **句柄管理**：内置 `Handle` 系统级句柄页面，可按进程、类型、对象和风险视角分析句柄，支持关闭、复制或降低句柄权限。
- **系统监控**：采集进程、线程、映像、注册表、文件与网络事件。
- **注册表与文件工具**：浏览、编辑、监控和配置保护规则。
- **窗口管理**：枚举窗口、修改窗口状态，并通过驱动配置窗口保护。
- **驱动与内核检查**：管理驱动服务，检查内核模块、对象、回调、MiniFilter、WFP、NDIS、安全状态和系统表。
- **驱动对象检查**：Driver Inspector 展示 IRP MajorFunction、Fast I/O dispatch、DeviceObject/AttachedDevice/NextDevice 链及函数地址符号归属。
- **内核分析视图**：`KernelInspector` 提供过滤器、网络、安全状态、同步对象与会话等内核检查能力。
- **内核研究中心**：通过 Microsoft 公共符号缓存解析内核地址归属，提供系统表完整性基线、Big Pool 聚合与对象命名空间浏览。
- **内存工具**：通过用户态 API 或 `AegisCore` 读取、写入和查看目标进程内存。
- **PatchGuard 绕过（双路径）**：主路径反汇编 `ntoskrnl!KeBugCheckEx` 精确解析 PG 相关符号与偏移，劫持 `HalPrivateDispatchTable` 建立早期 bugcheck 钩子，在 PG 校验失败触发蓝屏时恢复被打断的执行流；辅路径跨核清零 KPRCB 校验上下文并摘除 PG 校验 DPC。两条路径可叠加，`KernelInspector` 会展示解析进度、HAL 钩子状态与已拦截的 bugcheck 次数。
- **事务化内核写入**：写入立即执行，同时静默保存原值，执行写后读回验证、失败自动恢复、会话回滚和 JSONL 审计。
- **模块系统**：加载独立功能模块，仓库包含 ARP、HTTP/2 和 Payload 相关示例项目。
- **可定制界面**：QFluent 风格界面，支持主题颜色、背景、字体缩放、密度和窗口透明度设置。

驱动不可用时，部分查询会自动回退到 Windows 用户态 API；需要内核权限的操作会保持不可用并显示错误状态。

## 项目结构

```text
.
|-- AegisNT.cpp             # Qt 主程序与页面实现
|-- AegisNT.vcxproj         # 主程序 Visual Studio 工程
|-- AegisNT.slnx            # 主程序、驱动和模块解决方案
|-- Platform/               # 驱动通信、注入、权限与平台封装
|-- Drivers/
|   `-- Ring0Core/          # AegisCore、AegisSentinel 与 DiskDrv 内核实现
|       `-- Impl/AegisCore/Protect/
|           |-- PatchGuard.cpp        # PG 禁用/查询入口（双路径编排）
|           |-- PatchGuardDpc.cpp     # PG 校验 DPC 枚举与摘除
|           |-- PgInternals.h         # KeBugCheckEx 反汇编偏移解析
|           |-- PgHalCallbacks.h      # HalPrivateDispatchTable 劫持
|           |-- PgBugCheck.h          # bugcheck 现场/CONTEXT 解析
|           `-- PgExceptionHandler.h  # 早期 bugcheck 拦截与执行流恢复
|-- Module/                 # 模块 ABI、加载器与输出捕获
|-- ModulesProject/         # 独立模块项目
|-- Data/                   # 默认配置、图标及运行时数据
|-- Bin/                    # Release 输出与运行时依赖
|-- Installer/              # Inno Setup 安装脚本
`-- External/               # 第三方或辅助代码
```

## 页面与导航

当前桌面端页面按如下分组组织：

- **Information / Task / Monitor / Registry / File / Window**：基础系统信息、任务管理与用户态工具页。
- **Kernel / Overview**：`KernelInspector`
- **Kernel / Execution**：`Driver`、`ServiceManager`、`Handle`、`Memory`、`Table`、`Callback`
- **Kernel / Storage**：`Disk`
- **Module**：`Payload`、`ModuleRun`、`ModuleManager`
- **Console / Settings**：调试控制台与主题、语言、路径配置

## 环境要求

- Windows 10/11 x64
- Visual Studio 2022 或兼容的 MSVC x64 工具链
- Windows 10/11 SDK
- Qt 6.7.x，至少包含 `Core`、`Gui`、`Widgets` 和 `Network`
- Qt VS Tools / Qt MSBuild
- QFluent
- QWindowKit
- OpenSSL x64
- Windows Driver Kit，用于编译驱动
- Inno Setup 6，可选，仅用于生成安装程序

当前工程文件引用了开发机上的绝对路径，例如：

```text
D:\Qt\6.7.3\msvc2022_64
D:\OpenSSL-Win64
```

首次构建前，请在 `AegisNT.vcxproj` 或 Visual Studio 项目属性中将 Qt、QFluent、QWindowKit 和 OpenSSL 的包含目录、库目录及 DLL 路径改为本机位置。建议通过属性表或环境变量管理这些路径，避免提交个人路径。

## 构建

1. 安装上述依赖，并在 Qt VS Tools 中注册 MSVC 版本的 Qt。
2. 使用 Visual Studio 打开 `AegisNT.slnx`。
3. 选择 `x64` 和 `Release`。
4. 先构建 `Ring0Core` 及需要的模块，再构建 `AegisNT`。
5. 主程序 Release 输出位于 `Bin/`。

也可以在已初始化 MSVC 环境的终端中构建：

```powershell
msbuild AegisNT.slnx /m /p:Configuration=Release /p:Platform=x64
```

若出现以下错误：

```text
QMAKE_CXX.COMPILER_MACROS is not defined
QMAKE_MSC_VER isn't set
```

请确认命令运行在对应 Visual Studio Developer PowerShell/Command Prompt 中，并检查 Qt Kit 与 MSVC 工具集是否匹配。

## 运行与驱动

建议以管理员身份启动：

```powershell
.\Bin\AegisNT.exe
```

内核功能使用 `AegisCore` 设备通道，监控功能使用 `AegisSentinel` 设备通道；二者均由 `Ring0Core.sys` 提供。驱动必须与当前系统架构匹配并具有 Windows 接受的有效签名。开发环境中若使用测试签名，请仅在隔离测试机或虚拟机中配置相应启动策略。

驱动服务可按实际 `.sys` 路径创建并启动：

```powershell
sc.exe create Ring0Core type= kernel binPath= "C:\path\to\Ring0Core.sys"
sc.exe start Ring0Core
```

停止服务：

```powershell
sc.exe stop Ring0Core
```

设备打开失败时，请检查管理员权限、服务状态、驱动签名、系统事件日志，以及驱动和主程序的通信结构是否来自同一次构建。

## 配置与模块

默认配置位于 `Data/Config.json`，运行时资源和模块通常从 `Bin/Data`、`Bin/Drivers`、`Bin/Modules` 与 `Bin/ExtraDLL` 加载。不要提交包含私钥、令牌、目标地址或其他敏感信息的本地配置。

模块通过 `Module/` 中定义的接口加载。新增模块时应保持 ABI 一致，并将生成的 DLL 及其依赖部署到 `Bin/Modules` 对应目录。`ModulesProject/` 中的项目可作为结构参考。

## 安装程序

`Installer/AegisNT.iss` 使用 Inno Setup 打包应用，并可选择安装 VC++ Runtime、Npcap 和 HTTP 检查证书。生成安装程序前必须修改脚本顶部的 `SourceDir` 与 `DepDir`，并重新核对证书主题和指纹。

不要分发仓库中的开发证书私钥。正式发布时应生成独立证书，安全保存私钥，并更新安装脚本中的证书信息。

## PatchGuard 绕过机制

驱动实现了两条互补的路径（`Drivers/Ring0Core/Impl/AegisCore/Protect/`）：

### 主路径：早期 bugcheck 拦截

思路参考 [ByePg](https://github.com/can1357/ByePg) 的 exception-hooking：

1. **确定性偏移解析**（`PgInternals.h`）
   反汇编 `ntoskrnl!KeBugCheckEx` 的指令流，用机器码模式精确取出
   `KiHardwareTrigger`、`KeBugCheck2`、`KiBugCheckActive`、
   `_KPRCB.Context`、`_KPCR.DebuggerSavedIrql`、`KiFreezeExecutionLock`
   等符号与偏移。解析分 7 个阶段，任一阶段失败都记录在 `ResolveStage`
   位掩码中并经 IOCTL 回报，便于定位问题。
   不使用版本静态表，也不使用"扫描猜偏移"的启发式。

2. **HAL 派发表劫持**（`PgHalCallbacks.h`）
   定位 `HalPrivateDispatchTable` 并按 `Version` 门槛择机替换
   `HalNotifyProcessorFreeze`、`HalTimerWatchdogStop`（或
   `HalPrepareForBugcheck`）、`HalRestoreHvEnlightenment`。
   这些例程必然在 bugcheck / 处理器冻结路径上被调用，因此能在"内核已决定
   蓝屏、但尚未重置机器"的窗口里拿到控制权。

3. **现场解析与执行流恢复**（`PgBugCheck.h` / `PgExceptionHandler.h`）
   从 `_KPRCB.Context` 还原 `KeBugCheckEx` 的参数，按 bugcheck code 的约定
   提取 `CONTEXT` 与 `EXCEPTION_RECORD`（必要时回退到栈扫描），
   复位 `KiBugCheckActive` / `KiHardwareTrigger` / `IpiFrozen`，
   最后用 `RtlRestoreContext` 跳回 bugcheck 之前——蓝屏被"吃掉"。

该路径**不修改 PatchGuard 自身状态**，因此不会破坏内核一致性。

### 辅路径：KPRCB 上下文清零

跨核清零 KPRCB 内保存的 PG 校验上下文指针，使周期性校验失去参照；
同时枚举并摘除携带失效上下文的 PG 校验 DPC（兼容 Win10 双链表与
Win11 24H2+ 单链表两种队列布局）。这条路径会改变 PG 状态，作为加固手段。

### 可观测性

`KernelInspector` 的 PatchGuard 区块展示：`PgContextOffset`、`IsPatched`、
`Intercept`（含解析阶段、HAL 版本、已装钩子）、`Suppressed`（已吃掉的
bugcheck 次数、freeze/bugcheck 通知次数、最近一次 code 与 RIP）、
`KprcbContextOffset` 以及 DPC 扫描摘要。驱动侧同步输出 `[PG-Resolve]`、
`[PG-HAL]`、`[PG-EX]` 前缀的 `DbgPrint` 日志。

### 字段语义（易误读，务必注意）

| UI 行 | 含义 |
| --- | --- |
| `PatchGuard.KprcbContextOffset` | `_KPRCB.Context` 在 KPRCB 结构内的**偏移**，取值量级约 `0x8000`。**不是地址**。 |
| `PatchGuard.Intercept` 的 `stage` | `PG_RESOLVE_STAGE_*` 位掩码，decoded 为 `ctx+irql+hwtrig+bc2+bcactive+freezelock+ntbase`。`0x7F` 为全部解析成功。 |
| `stage none (resolution never ran)` | 解析从未执行。查询操作现在会主动触发一次解析，正常不应再出现。 |
| `critical OK / INCOMPLETE` | `AllCriticalResolved`：拦截路径所需的全部关键项是否齐备。 |
| `KiHardwareTrigger` 等符号行 | 显示**完整地址**，未解析出来时显示 `unresolved (!)`。 |

> 早期版本这里只回填地址的低 32 位，导致页对齐地址（低 32 位为 0）看起来
> 与"解析失败"完全相同。现已改为完整地址 + 独立的有效标志。

> 拦截只对**可解析**的 bugcheck 生效。真正致命的内存损坏若无法还原
> `CONTEXT`，仍会正常蓝屏——这是有意的安全边界，避免在损坏的栈上继续执行。

## 安全说明

- 优先在虚拟机中测试驱动、注入、DSE、回调移除和内核内存操作。
- 操作关键进程、系统句柄或未知内核地址前先创建快照。
- 用户态回退结果可能受权限、PPL 和系统版本限制，不一定与内核视图完全一致。
- 驱动与 `Platform/AegisCoreCall.h` 的 IOCTL、结构大小和版本必须同步
  （`PG_CONTROL_OUTPUT` 两侧均有 `static_assert` 尺寸守卫）。
- PatchGuard 绕过依赖 `HalPrivateDispatchTable` 的版本门槛；HAL 版本过旧时
  主路径会拒绝挂钩并回报失败，此时只保留辅路径。
- 网络与 Payload 模块仅用于授权测试和防御研究。

## License

仓库当前未包含许可证文件。在添加明确的 `LICENSE` 前，默认保留全部权利，不应假定代码可以复制、修改或重新分发。
## Cross-platform servers

The standalone TCP chat server and HTTP license server support Windows and
Linux. Use the repository CMake project for both platforms:

```sh
cmake -S . -B build
cmake --build build --config Release
```

Use `-DAEGISNT_BUILD_CHAT_SERVER=OFF` or
`-DAEGISNT_BUILD_LICENSE_SERVER=OFF` to build only one server. Linux requires
a C++20 toolchain plus OpenSSL, SQLite3, cpp-httplib, and nlohmann/json
development packages.
