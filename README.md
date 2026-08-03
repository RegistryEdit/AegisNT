# AegisNT

[中文](README.md) | [English](README_EN.md)

AegisNT 是一个面向 Windows x64 的系统检查、进程管理和内核调试工具。主程序使用 C++20、Qt 6 和 QFluent 构建，并通过 `MultiDrv` 与 `MonitorDrv` 驱动扩展用户态 API 无法完成的查询、保护和操作能力。

> 本项目包含进程终止、句柄关闭、内存读写、驱动加载、DLL 注入和安全策略修改等高权限功能。请仅在自己拥有或明确获准测试的设备上使用。错误使用可能导致应用崩溃、系统不稳定或蓝屏。

## 功能概览

- **系统与任务管理**：查看进程、线程、令牌、模块、内存、PEB、句柄及缓解策略，支持实时刷新和详细检查。
- **进程操作**：终止、挂起、恢复、设置 PPL/关键进程状态、令牌操作、DLL 注入及进程保护。
- **句柄管理**：内置 `HandleLab` 系统级句柄实验室，可按进程、类型、对象和风险视角分析句柄，支持关闭、复制或降低句柄权限。
- **系统监控**：采集进程、线程、映像、注册表、文件与网络事件。
- **注册表与文件工具**：浏览、编辑、监控和配置保护规则。
- **窗口管理**：枚举窗口、修改窗口状态，并通过驱动配置窗口保护。
- **驱动与内核检查**：管理驱动服务，检查内核模块、对象、回调、MiniFilter、WFP、NDIS、安全状态和系统表。
- **驱动对象检查**：Driver Inspector 展示 IRP MajorFunction、Fast I/O dispatch、DeviceObject/AttachedDevice/NextDevice 链及函数地址符号归属。
- **内核分析视图**：`KernelInspector` 提供过滤器、网络、安全状态、同步对象与会话等内核检查能力。
- **内核研究中心**：通过 Microsoft 公共符号缓存解析内核地址归属，提供系统表完整性基线、Big Pool 聚合与对象命名空间浏览。
- **内存工具**：通过用户态 API 或 `MultiDrv` 读取、写入和查看目标进程内存。
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
|   |-- MultiDrv/           # 内核查询、保护和系统操作驱动
|   `-- MonitorDrv/         # 系统、文件和网络事件监控驱动
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
- **Kernel / Research**：`KernelResearch`（Symbols、Address Ownership、Integrity、Big Pool、Objects）
- **Kernel / Execution**：`Driver`、`ServiceManager`、`HandleLab`、`Memory`、`Table`、`Callback`
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
4. 先构建 `MultiDrv`、`MonitorDrv` 及需要的模块，再构建 `AegisNT`。
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

内核功能依赖 `MultiDrv`，监控功能依赖 `MonitorDrv`。驱动必须与当前系统架构匹配并具有 Windows 接受的有效签名。开发环境中若使用测试签名，请仅在隔离测试机或虚拟机中配置相应启动策略。

驱动服务可按实际 `.sys` 路径创建并启动：

```powershell
sc.exe create MultiDrv type= kernel binPath= "C:\path\to\MultiDrv.sys"
sc.exe start MultiDrv

sc.exe create MonitorDrv type= kernel binPath= "C:\path\to\MonitorDrv.sys"
sc.exe start MonitorDrv
```

停止服务：

```powershell
sc.exe stop MonitorDrv
sc.exe stop MultiDrv
```

设备打开失败时，请检查管理员权限、服务状态、驱动签名、系统事件日志，以及驱动和主程序的通信结构是否来自同一次构建。

## 配置与模块

默认配置位于 `Data/Config.json`，运行时资源和模块通常从 `Bin/Data`、`Bin/Drivers`、`Bin/Modules` 与 `Bin/ExtraDLL` 加载。不要提交包含私钥、令牌、目标地址或其他敏感信息的本地配置。

模块通过 `Module/` 中定义的接口加载。新增模块时应保持 ABI 一致，并将生成的 DLL 及其依赖部署到 `Bin/Modules` 对应目录。`ModulesProject/` 中的项目可作为结构参考。

## 安装程序

`Installer/AegisNT.iss` 使用 Inno Setup 打包应用，并可选择安装 VC++ Runtime、Npcap 和 HTTP 检查证书。生成安装程序前必须修改脚本顶部的 `SourceDir` 与 `DepDir`，并重新核对证书主题和指纹。

不要分发仓库中的开发证书私钥。正式发布时应生成独立证书，安全保存私钥，并更新安装脚本中的证书信息。

## 安全说明

- 优先在虚拟机中测试驱动、注入、DSE、回调移除和内核内存操作。
- 操作关键进程、系统句柄或未知内核地址前先创建快照。
- 用户态回退结果可能受权限、PPL 和系统版本限制，不一定与内核视图完全一致。
- 驱动与 `Platform/MultiDrvCall.h` 的 IOCTL、结构大小和版本必须同步。
- 网络与 Payload 模块仅用于授权测试和防御研究。

## License

仓库当前未包含许可证文件。在添加明确的 `LICENSE` 前，默认保留全部权利，不应假定代码可以复制、修改或重新分发。
