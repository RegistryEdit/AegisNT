# AegisNT

[中文](README.md) | [English](README_EN.md)

**面向 Windows x64 的系统管理、行为监控与内核分析工具。**

AegisNT 将进程、线程、内存、文件、注册表、窗口、网络和内核对象的检查与管理集中在一个桌面界面中。客户端使用 **C++20、Qt 6、QFluent 和 QWindowKit**，通过统一驱动 `Ring0Core.sys` 提供内核查询、保护规则与底层操作能力，并支持 DLL 功能模块扩展。

项目还包含独立的 TCP 聊天服务端和 HTTP 账户服务端。**桌面端与驱动面向 Windows；这两个服务端提供 Windows / Linux 的 CMake 构建入口。**

## 功能

### 系统与进程管理

- **系统概览**：查看运行环境、驱动状态、CPU、内存、磁盘和网络等信息。
- **任务管理**：进程与线程枚举、搜索和刷新；支持终止、挂起、恢复、进程启动及创建阻止规则。
- **进程详情**：集中查看令牌、线程、句柄、模块、内存区域、`EPROCESS`、PEB 和缓解策略。
- **高级进程操作**：进程保护、PPL / 关键进程状态、令牌操作及 DLL 注入。
- **句柄操作**：在进程详情的 `Handles` 标签中查看对象类型与访问权限，支持强制关闭、复制和权限降级。
- **服务管理**：枚举服务与驱动服务，查看启动类型、运行状态、PID 和映像路径，执行启动、停止、重启与删除。

### 行为监控与网络管控

- **系统监控**：提供 ETW 与内核监控模式，采集进程、线程、映像、文件、注册表和网络等事件。
- **多视图监控**：包含 System、Process、Network、HTTP(S)、History、Rules、Devices 和 Alerts；支持事件过滤、详情查看及历史记录 CSV 导出。
- **监控规则**：管理文件、注册表与网络的审计 / 阻止规则，支持规则导入和导出。
- **HTTP(S) 检查**：查看请求、响应、头部与正文；HTTPS 检查依赖本地代理及检查证书。
- **连接表**：查看 IPv4 / IPv6 TCP、UDP 连接及关联进程。
- **WFP 防火墙规则**：按协议、远程地址、远程端口、方向和地址族添加阻止 / 放行规则，并支持删除与清空。

### 文件、注册表、窗口与热键

- **文件管理**：文件浏览、属性查看、删除 / 强制删除、文件保护及目录变更监控。
- **注册表管理**：浏览键和值，创建、修改、删除内容；提供启动项、映像劫持项视图和保护规则。
- **窗口管理**：枚举窗口、查看所属进程、调整窗口状态，并管理窗口保护列表。
- **全局热键**：枚举已注册热键，展示 PID、进程名、组合键、ID 与内核对象地址；支持搜索、自动刷新和移除选中热键。

### 驱动与内核分析

- **驱动检查**：枚举内核驱动、加载 / 卸载驱动，查看 DriverObject、IRP MajorFunction、Fast I/O 和设备链。
- **KernelInspector**：检查 MiniFilter、WFP、NDIS、安全状态、同步对象和会话，并提供内核调试、DSE 与 PatchGuard 控制入口。
- **系统表**：查看 IDT、GDT、SSDT、ShadowSSDT、I/O Timer、DPC、PiDDBCacheTable、CPU 寄存器、MSR 监视及 HAL 派发表。
- **回调检查**：查看内核回调及所属模块，管理支持的回调注册项。
- **内核研究**：符号解析、地址归属、完整性基线、Big Pool 汇总、对象命名空间、Rootkit 异常线索和内核模式扫描。
- **Hook 管理**：安装、启用、禁用、校验、移除和恢复受支持的钩子；当前实现覆盖 DriverDispatch、`FastIoCheckIfPossible`、SSDT、当前 CPU 的 IDT 和 x64 Inline。

符号服务使用 Microsoft 公共符号服务器，缓存位于程序目录下的 `Data/SymbolCache`。依赖内部结构或动态偏移的查询与操作，以当前系统上的解析结果和驱动返回状态为准。

### 内存、快照与磁盘

- **内存工具**：查看进程 / 内核内存、物理内存信息，执行可疑内存扫描，以及进程内存分配、释放和保护属性修改。
- **内存写入校验**：写入前读取原值，写入后读回比对；校验失败时尝试恢复原值，提供当前页面会话中最近一次成功写入的 `Rollback Last`。
- **写入审计**：成功校验的写入记录到 `Data/Audit/kernel-write-YYYYMMDD.jsonl`。该日志记录事务元数据，不是完整内存备份。
- **快照对比**：捕获进程、驱动和回调快照，保存 / 加载 JSON，进行 A/B 对比，展示新增、删除和修改项，并支持定时基线检查。
- **磁盘保护**：查看磁盘与分区信息，配置保护 / 仅审计模式，检查阻止事件，处理当前请求或一次性放行令牌，并读取保护范围或自定义范围内的扇区。

### 模块、账户与界面

- **模块管理与运行**：扫描 DLL 模块和驱动，加载 / 卸载、配置参数、执行模块、查看输出；模块类型包含 `Auxiliary`、`Exploit`、`Payload` 和 `Post`。
- **Payload 工具**：提供负载生成与远程会话相关入口；本地模块项目包含 ARP、HTTP/2 与 Payload 示例。
- **账户**：登录、注册、记住凭据、自动登录、修改密码及管理员用户类型管理。
- **聊天**：连接独立 TCP 服务端，查看在线用户并发送公共 / 私聊消息。
- **控制台**：汇总应用与模块输出，执行命令并查看结果。
- **个性化**：中英文切换、明暗主题、主题配色、Mica / Acrylic、壁纸、字体缩放、界面密度、透明度、托盘与全局唤起热键；设置页提供更新检查入口。

## 页面导航

当前注册并接入导航的页面共 **25 个**，分组如下：

| 导航位置 | 页面 |
| --- | --- |
| 顶层系统工具 | `Information`、`Task`、`Monitor`、`Registry`、`File`、`Window` |
| Kernel → Overview | `KernelInspector`、`KernelResearch`、`HotKeys` |
| Kernel → Execution | `Driver`、`ServiceManager`、`Network`、`Hook`、`Memory`、`Table`、`Callback` |
| Kernel → Storage | `Snapshot`、`Disk` |
| Module | `Payload`、`ModuleRun`、`ModuleManager` |
| 顶层辅助页面 | `Console`、`Chat`、`Account`、`Settings` |

页面定义见 [PageRegistry.cpp](Source/Pages/PageRegistry.cpp)，创建与导航分组见 [AegisNT.cpp](AegisNT.cpp)。`HandleLabPage` 源文件目前未接入独立导航，句柄管理的实际入口是 `Task` 的进程详情。

## 运行条件与组件

桌面端面向 **Windows 10 / 11 x64**，完整功能需要管理员权限。依赖内核内部结构的功能不保证在所有系统构建上可用。

| 组件 | 用途 | 使用条件 |
| --- | --- | --- |
| `AegisNT.exe` | 桌面客户端 | Qt、QFluent、QWindowKit、OpenSSL 等运行时依赖完整 |
| `Ring0Core.sys` | 内核查询、控制、监控与磁盘保护 | 与客户端协议匹配，并满足当前系统的驱动加载条件 |
| `LicenseServer` | 账户认证、用户管理与更新信息 | **进入主窗口前需要可访问的服务端** |
| `Server` | TCP 聊天 | 仅聊天功能需要 |
| `MonitorHook.dll` | 目标进程监控 | 使用 Process 监控时需要 |
| WinDivert | 网络捕获和 HTTP(S) 检查 | 对应 DLL 可加载，驱动已安装并运行 |
| Npcap 及模块依赖 | 部分 ARP 等网络模块 | 按具体模块准备 |

`Ring0Core.sys` 是一个统一驱动，通过三个设备通道提供不同能力：

| 设备通道 | 职责 |
| --- | --- |
| `\\.\AegisCore` | 进程、线程、内存、窗口、服务、网络规则及内核检查 / 操作 |
| `\\.\AegisSentinel` | 内核事件、监控队列、过滤与审计 / 阻止规则 |
| `\\.\DiskDrv` | 磁盘保护、阻止事件与一次性放行 |

部分查询在驱动不可用时提供用户态回退；这不代表全部页面或操作都能在无驱动环境下运行。

## 首次运行

1. 准备客户端及运行时依赖；默认 Release 程序目录为 `Bin/`。
2. 启动 `LicenseServer`，或准备已有的可访问账户服务。默认监听 HTTP `8888` 端口。
3. 检查 **程序目录下** 的 `Data/Config.json`，将 `LicenseServer.Address` 设置为实际服务地址；默认值为 `http://localhost:8888`。
4. 以管理员身份运行客户端，在登录对话框中注册或使用已有账户登录。当前启动流程在认证成功后才创建主窗口；自动登录也需要重新认证。
5. 使用内核功能时，将匹配版本的 `Ring0Core.sys` 放入配置的驱动目录，检查驱动加载状态。默认配置启用模块与驱动自动加载。
6. 按需准备进程监控、网络捕获、HTTP(S) 或聊天组件。

```powershell
.\Bin\AegisNT.exe
```

常见运行时目录如下；其中部分目录和文件按功能使用情况生成或部署：

```text
Bin/
├── AegisNT.exe
├── Data/
│   ├── Config.json
│   ├── SymbolCache/
│   └── Audit/
├── Drivers/
│   └── Ring0Core.sys
├── Modules/
├── ExtraDLL/
│   ├── MonitorHook.dll
│   └── WinDivert.dll
└── tls/
    └── qschannelbackend.dll
```

HTTPS 检查使用 `Data/CA_CERT.pem` 与 `Data/CA_KEY.pem`，并要求被检查客户端信任对应证书。配置与部署说明不意味着所有目标程序都能被解密检查。

## 从源码构建

### 桌面端与驱动

先核对工程中实际使用的工具链和路径：

| 项目 | 当前工程配置 |
| --- | --- |
| C++ | C++20，x64 |
| MSVC | `PlatformToolset=v145` |
| Qt | `6.7.3/msvc2022_64`，Core、Gui、Widgets、Network |
| Qt 构建集成 | Qt VS Tools / Qt MSBuild |
| UI 依赖 | QFluent、QWindowKit |
| 加密 / HTTP 检查 | OpenSSL x64 |
| 驱动 | WDK，`WindowsKernelModeDriver10.0`；目标 SDK 版本 `10.0.28000.0` |

这些是当前项目文件的配置值，并非所有可用版本的兼容性声明。更换工具链时，需要同步调整项目属性、Qt Kit、第三方库与驱动构建配置。

1. 安装相应 MSVC、Windows SDK / WDK、Qt 及第三方依赖。
2. 修改 [AegisNT.vcxproj](AegisNT.vcxproj) 中的本机路径，包括 Qt、Qt MSBuild、QFluent、QWindowKit 属性表及 OpenSSL 的包含 / 库目录和部署路径。工程目前包含 `D:\Qt\6.7.3\msvc2022_64`、`D:\OpenSSL-Win64` 等绝对路径。
3. 使用支持 `.slnx` 的 Visual Studio / MSBuild 打开 [AegisNT.slnx](AegisNT.slnx)，选择 `Release | x64`。
4. 按需构建 `AegisNT`、`Ring0Core`、`LicenseServer` 及模块项目。主程序输出到 `Bin/`，驱动工程的 Release x64 输出到 `Bin/Drivers/`。
5. 需要 Process 监控时，单独构建 `Platform/HookDLL/HookDLL.vcxproj`，将 `MonitorHook.dll` 部署到 `Bin/ExtraDLL/`；该工程未列入主解决方案。
6. 部署相应 Qt 插件和第三方运行库后，按“首次运行”配置账户服务并启动客户端。

完整解决方案的命令行构建入口：

```powershell
# 在已初始化对应 MSVC 环境的 Developer PowerShell 中执行
msbuild AegisNT.slnx /m /p:Configuration=Release /p:Platform=x64
```

完整解决方案还引用了服务端和独立模块；这些项目的源码与依赖也必须齐全。只构建桌面工程时，可在仓库根目录执行：

```powershell
msbuild AegisNT.vcxproj /m /p:Configuration=Release /p:Platform=x64 /p:OutDir=Bin\
```

> 当前 `.gitignore` 忽略了 `Drivers/`、`ModulesProject/`、`Server/`、`LicenseServer/`、`Tests/` 等目录。本地工作区存在这些源码，不代表从 Git 获取的副本也包含它们；构建前请确认所需文件齐全。根目录的 `build_ui.cmd`、`build_driver_full.cmd` 也包含开发机专用路径，需要按本机环境调整。

### 独立服务端

根目录的 [CMakeLists.txt](CMakeLists.txt) **只构建聊天服务端和账户服务端**，不构建 Qt 客户端或内核驱动。

要求 CMake 3.20+ 和 C++20 工具链。账户服务端还依赖 OpenSSL、SQLite3、`cpp-httplib` 和 `nlohmann/json`；应先安装并确保 CMake 能找到它们。

```sh
cmake -S . -B build-server
cmake --build build-server --config Release
```

可通过选项只构建其中一个服务：

```sh
# 只构建账户服务端
cmake -S . -B build-license -DAEGISNT_BUILD_CHAT_SERVER=OFF
cmake --build build-license --config Release --target LicenseServer

# 只构建聊天服务端
cmake -S . -B build-chat -DAEGISNT_BUILD_LICENSE_SERVER=OFF
cmake --build build-chat --config Release --target Server
```

| 服务 | 默认监听 | 客户端配置 |
| --- | --- | --- |
| `LicenseServer` | `0.0.0.0:8888`，HTTP | `LicenseServer.Address` |
| `Server` | `0.0.0.0:1145`，TCP | `Chat.ServerIP`、`Chat.ServerPort` |

可执行文件位置取决于 CMake 生成器，多配置生成器通常使用 `Release/` 子目录。`LicenseServer` 将 `LicenseServer.db` 保存在工作目录中；更新信息使用 `UpdateConfig.json`，CMake 会将其复制到构建目录。

## 配置与扩展

配置模板为 [Data/Config.json](Data/Config.json)，程序实际读写的是可执行文件旁的 `Data/Config.json`。初次构建只在目标配置不存在时复制模板，已有运行时配置不会被模板覆盖。

| 配置节 | 主要内容 |
| --- | --- |
| `Application` | 语言、窗口尺寸、透明度等 |
| `Theme` | 明暗主题、配色、壁纸、材质、字体与密度 |
| `Drivers` | `Paths` 驱动目录、`AutoLoad` 自动加载 |
| `Modules` | `Paths` 模块目录、`AutoLoad` 自动加载 |
| `LicenseServer` | 账户服务地址 |
| `Chat` | 聊天服务地址、端口与用户名 |
| `Payload` / `PayloadShell` | 负载选项与会话连接配置 |

模块与驱动的相对路径按程序目录解析。模块扫描读取每个配置目录的直接子文件；使用额外子目录时，需要将其加入 `Paths`。

新增 DLL 模块时，参考 [ModuleBase.h](Module/ModuleBase.h) 与现有模块项目：

1. 继承 `ModuleBase`，实现 `Info()`、`Run()`，按需覆写 `Check()`。
2. 通过 `RegisterOption()` 注册参数，并导出 `CreateModule` / `DestroyModule`。
3. 对需要中止的长时间任务，按现有约定提供 `StopModule`。
4. 使用与主程序兼容的 x64 编译器、运行库及接口定义，将 DLL 和依赖部署到配置的模块目录。

[ModuleTemplate.cpp](ModuleTemplate.cpp) 是需要补全的结构草稿，不能直接作为可编译模块使用。

## 源码结构

```text
AegisNT.cpp                 主程序入口、页面装配与导航
AegisNT.vcxproj             Qt 桌面工程
AegisNT.slnx                桌面、驱动、服务端与模块解决方案
CMakeLists.txt              独立服务端跨平台构建
Source/
├── AppContext.*            应用共享状态
├── Auth/                   认证与凭据处理
├── Core/                   配置、主题、模块和会话运行时
├── Dialogs/                登录与注册
├── Pages/                  各功能页面
└── KernelResearch.h        符号服务与内核研究辅助
Platform/                   驱动通信、系统 API、注入与监控封装
Drivers/Ring0Core/           统一驱动与通信协议
Module/                     模块基类、参数及输出捕获
ModulesProject/             独立模块项目
Server/                     TCP 聊天服务端
LicenseServer/              HTTP 账户服务端
Data/                       默认配置、语言资源及检查证书相关文件
Installer/                  Inno Setup 安装脚本
Tests/                      专项测试与回归样例
External/                   第三方与辅助代码
Bin/                        桌面 Release 输出和运行时资源
```

桌面页面与多个运行时实现通过 `#include` 合入 `AegisNT.cpp`；驱动也通过 `Driver.cpp` 组织统一编译。修改项目文件时，应保留这一组织方式，避免重复编译已被包含的实现文件。

## 常见问题

| 现象 | 检查项 |
| --- | --- |
| 登录失败，无法进入主窗口 | 账户服务是否启动，`LicenseServer.Address` 是否正确，端口是否可达，账户是否有效 |
| Qt MSBuild 找不到或出现 `QMAKE_CXX.COMPILER_MACROS` / `QMAKE_MSC_VER` 错误 | Qt MSBuild 路径、MSVC 环境、Qt Kit 与工具链是否匹配 |
| 启动提示缺失 DLL 或 Qt 插件 | Qt、QFluent、QWindowKit、OpenSSL 和平台 / TLS 插件是否正确部署 |
| 内核查询失败或显示 unavailable | 管理员权限、驱动服务状态、驱动加载条件、系统版本及客户端 / 驱动协议是否匹配 |
| Process 监控无法启动 | `ExtraDLL/MonitorHook.dll` 是否存在，目标架构和注入方式是否适用 |
| Network / HTTP(S) 捕获失败 | WinDivert DLL、驱动状态和代理端口；HTTPS 还需检查证书配置；两种捕获模式不能同时启动 |
| 模块没有显示 | 配置目录、DLL 依赖、模块导出和 ABI 是否正确；扫描不递归子目录 |

## 实验性功能与使用边界

进程 / 句柄强制操作、内核写入、回调移除、Hook、磁盘保护以及 DSE / PatchGuard 控制可能影响系统稳定性。请仅在获得授权的设备上使用，并优先在可恢复的测试环境中验证。

PatchGuard 相关实现包含早期 bugcheck 拦截、KPRCB 上下文与 DPC 处理，界面显示解析阶段、状态及相关计数。**存在控制入口不等于在任意 Windows 构建上有效，也不保证避免蓝屏。** 内存回滚只覆盖当前页面保留的最近一次写入，不提供完整会话或跨重启恢复。

客户端与驱动的 IOCTL 和结构布局需要同步；升级时应配套更新。HTTPS 检查私钥、账户凭据与服务端签名配置应按部署环境独立管理，不要直接分发开发配置。

## 打包与许可

安装程序使用 `Installer/AegisNT.iss`，提供 VC++ Runtime、Npcap 和 HTTP 检查证书的可选安装。打包前需要调整 `SourceDir`、`DepDir`、依赖文件及证书信息。

当前仓库未提供项目级 `LICENSE` 文件；项目使用许可需由维护者明确，第三方组件遵循各自许可证。
