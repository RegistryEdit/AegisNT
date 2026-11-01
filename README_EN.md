# AegisNT

[中文](README.md) | [English](README_EN.md)

**System management, activity monitoring, and kernel analysis for Windows x64.**

AegisNT brings process, thread, memory, file, registry, window, network, and kernel inspection into one desktop application. Built with **C++20, Qt 6, QFluent, and QWindowKit**, it uses the unified `Ring0Core.sys` driver for kernel queries, protection rules, and low-level operations, with DLL modules for additional functionality.

The project also includes a standalone TCP chat server and an HTTP account server. **The desktop application and driver target Windows; the two servers have CMake build support for Windows and Linux.**

## Features

### System and process management

- **System overview**: Inspect the runtime environment, driver status, CPU, memory, disks, and network information.
- **Task management**: Enumerate, search, and refresh processes and threads; terminate, suspend, resume, launch processes, and manage process creation blocking rules.
- **Process inspector**: Inspect tokens, threads, handles, modules, memory regions, `EPROCESS`, PEB data, and mitigation policies.
- **Advanced process operations**: Manage process protection, PPL / critical-process state, tokens, and DLL injection.
- **Handle operations**: Use the process inspector's `Handles` tab to inspect object types and access rights, force-close or duplicate handles, and reduce their permissions.
- **Service management**: Inspect services and driver services, startup types, states, PIDs, and image paths; start, stop, restart, and delete services.

### Activity monitoring and network control

- **System monitoring**: ETW and kernel modes collect process, thread, image, file, registry, network, and other events.
- **Monitoring views**: System, Process, Network, HTTP(S), History, Rules, Devices, and Alerts, with filtering, event details, and CSV history export.
- **Monitoring rules**: Manage audit / block rules for files, the registry, and networking, with rule import and export.
- **HTTP(S) inspection**: Inspect requests, responses, headers, and bodies; HTTPS inspection requires a local proxy and an inspection certificate.
- **Connection table**: Inspect IPv4 / IPv6 TCP and UDP endpoints and their owning processes.
- **WFP firewall rules**: Add block / permit rules by protocol, remote address, remote port, direction, and address family; remove individual rules or clear them.

### Files, registry, windows, and hotkeys

- **Files**: Browse files, inspect properties, delete / force-delete files, manage protection, and monitor directory changes.
- **Registry**: Browse keys and values; create, edit, and delete entries; inspect startup and image-hijack entries and manage protection rules.
- **Windows**: Enumerate windows, inspect ownership, change window state, and manage window protection.
- **Global hotkeys**: Enumerate registered hotkeys with PIDs, process names, key combinations, IDs, and kernel object addresses; search, refresh automatically, and remove selected registrations.

### Drivers and kernel analysis

- **Driver inspection**: Enumerate, load, and unload drivers; inspect DriverObject, IRP MajorFunction entries, Fast I/O, and device chains.
- **KernelInspector**: Inspect MiniFilters, WFP, NDIS, security state, synchronization objects, and sessions, with controls for kernel debugging, DSE, and PatchGuard.
- **System tables**: Inspect IDT, GDT, SSDT, ShadowSSDT, I/O timers, DPCs, PiDDBCacheTable, CPU registers, MSR monitoring, and HAL dispatch tables.
- **Callbacks**: Inspect callback registrations and module ownership, and manage supported registrations.
- **Kernel research**: Symbol resolution, address ownership, integrity baselines, Big Pool aggregation, object namespaces, rootkit indicators, and kernel pattern scanning.
- **Hook management**: Install, enable, disable, verify, remove, and restore supported hooks. Current targets include DriverDispatch, `FastIoCheckIfPossible`, SSDT, the current CPU's IDT, and x64 Inline.

The symbol service uses the Microsoft public symbol server and caches files under `Data/SymbolCache` beside the executable. Queries and operations that depend on internal structures or dynamic offsets are subject to runtime resolution and driver status.

### Memory, snapshots, and disks

- **Memory tools**: Inspect process / kernel memory and physical memory information, scan suspicious memory, and allocate, free, or change protection on process memory.
- **Write verification**: Read original bytes before writing and verify by reading back afterward. Failed verification triggers an attempt to restore the original bytes. `Rollback Last` covers the most recent successful write retained by the current page session.
- **Write audit**: Verified writes are recorded in `Data/Audit/kernel-write-YYYYMMDD.jsonl`. The log contains transaction metadata, not a complete memory backup.
- **Snapshot comparison**: Capture process, driver, and callback snapshots; save / load JSON; compare A/B snapshots for additions, removals, and changes; schedule baseline checks.
- **Disk protection**: Inspect disk and partition information, configure protection / audit-only mode, inspect blocked events, handle current requests or one-shot allow tokens, and read sectors from protected or custom ranges.

### Modules, accounts, and interface

- **Module management and execution**: Discover DLL modules and drivers, load / unload them, configure parameters, run modules, and inspect output. Module categories include `Auxiliary`, `Exploit`, `Payload`, and `Post`.
- **Payload tools**: Payload generation and remote-session interfaces; local module projects include ARP, HTTP/2, and payload examples.
- **Accounts**: Login, registration, remembered credentials, automatic login, password changes, and administrator user-type management.
- **Chat**: Connect to the standalone TCP server, view online users, and send public or private messages.
- **Console**: Collect application and module output, execute commands, and inspect results.
- **Customization**: English / Chinese switching, light / dark themes, colors, Mica / Acrylic, wallpaper, font scaling, density, opacity, system tray integration, and a global window activation hotkey. Settings also provides update checking.

## Navigation

There are currently **25 registered pages connected to navigation**:

| Navigation group | Pages |
| --- | --- |
| Top-level system tools | `Information`, `Task`, `Monitor`, `Registry`, `File`, `Window` |
| Kernel → Overview | `KernelInspector`, `KernelResearch`, `HotKeys` |
| Kernel → Execution | `Driver`, `ServiceManager`, `Network`, `Hook`, `Memory`, `Table`, `Callback` |
| Kernel → Storage | `Snapshot`, `Disk` |
| Module | `Payload`, `ModuleRun`, `ModuleManager` |
| Top-level supporting pages | `Console`, `Chat`, `Account`, `Settings` |

See [PageRegistry.cpp](Source/Pages/PageRegistry.cpp) for page definitions and [AegisNT.cpp](AegisNT.cpp) for page creation and navigation groups. The `HandleLabPage` source is not currently connected to standalone navigation; use the process inspector in `Task` for handle management.

## Runtime requirements and components

The desktop application targets **Windows 10 / 11 x64** and requires administrator privileges for full functionality. Features that depend on kernel internals are not guaranteed to work on every Windows build.

| Component | Purpose | Requirement |
| --- | --- | --- |
| `AegisNT.exe` | Desktop client | Qt, QFluent, QWindowKit, OpenSSL, and other runtime dependencies |
| `Ring0Core.sys` | Kernel queries, control, monitoring, and disk protection | Matching client protocol and a driver accepted by the current system |
| `LicenseServer` | Authentication, user management, and update information | **Must be reachable before entering the main window** |
| `Server` | TCP chat | Required only for chat |
| `MonitorHook.dll` | Target process monitoring | Required for the Process monitoring view |
| WinDivert | Network capture and HTTP(S) inspection | Loadable DLL and an installed, running driver |
| Npcap and module dependencies | Some ARP and other network modules | Depends on the selected module |

The unified `Ring0Core.sys` driver exposes three device channels:

| Device channel | Responsibility |
| --- | --- |
| `\\.\AegisCore` | Processes, threads, memory, windows, services, network rules, and kernel inspection / operations |
| `\\.\AegisSentinel` | Kernel events, monitoring queues, filters, and audit / block rules |
| `\\.\AegisDisk` | Disk protection, blocked events, and one-shot allow tokens |

Some queries fall back to user-mode APIs when the driver is unavailable. This does not make every page or operation available without a driver.

## First run

1. Prepare the client and its runtime dependencies. The default desktop Release directory is `Bin/`.
2. Start `LicenseServer` or make an existing account service available. Its default HTTP port is `8888`.
3. Edit `Data/Config.json` **beside the executable** and set `LicenseServer.Address` to the service address. The default is `http://localhost:8888`.
4. Run the client as an administrator. Sign in through the startup dialog or choose **Skip** for a guest session. Local tools remain available; `Account` and `Chat` require sign-in. Automatic login still reauthenticates.
5. For kernel features, place a matching `Ring0Core.sys` in the configured driver directory and check its load status. Module and driver automatic loading are enabled in the default configuration.
6. Prepare process monitoring, network capture, HTTP(S), and chat components as needed.

```powershell
.\Bin\AegisNT.exe
```

### Standalone terminal (separate from the GUI Console page)

```powershell
.\Bin\AegisNT.exe --console
.\Bin\AegisNT.exe --console --skip-login
```

`--console` uses an independent terminal by default: a GUI-subsystem executable's parent cmd/PowerShell may otherwise keep reading the same keyboard buffer, corrupting login input with prompts such as `More?`. To explicitly reuse PowerShell, use `Start-Process .\Bin\AegisNT.exe -ArgumentList '--console --reuse-console --skip-login' -NoNewWindow -Wait`; keep `-Wait`.

- Press **Enter / S** at the session menu to continue as guest immediately. `--skip-login` also skips automatic login; persisted account state is never treated as authentication.
- Saved automatic credentials are offered as **A** at the menu. Startup presents usable input before making any login request, so an unavailable server does not block local tools.
- Use `login` to sign in later; cancelling or skipping keeps guest access. `logout` clears the session and saved credentials.
- `pages` lists tools without initializing them. `use Task` or `2` at the home prompt selects a page; English names, translated names and unambiguous abbreviations work. `back` returns home; `help` lists page commands.
- Two-line prompts show `[HH:mm:ss] AegisNT > File > guest > current path`, followed by `╰─ >` for input. Cyan identifies the brand/page; time and session use muted gray. Narrow windows use tighter spacing; long prompt paths have a middle ellipsis while listing headings keep the full path. Each new prompt samples local time.
- Independent classic-console windows use Windows' built-in Consolas. `--reuse-console` keeps the host font. Background and palette stay host-owned; no font installation or terminal framework is required.
- Entering a page, switching views, or executing a page command displays its data after asynchronous enumeration completes. `show` / `ls` / `list` / `dir` work on every page; `refresh` reloads. Loading feedback appears only after 300 ms, with elapsed time on completion; the 10-second wait limit is unchanged.
- File supports `dir`, `ls [path]`, `list [path]`, `cd "C:\folder"`, relative `cd child` / `cd ..`, `pwd`, `up`, and `prev` / `forward` history navigation. `back` always returns to the home prompt; use `use` for switching pages.
- Active tables default to 20 rows per page: `show 2`, `next-page`, `prev-page`, or `show all`. Paging reads the last display snapshot without re-enumeration. Refresh, filtering, page entry and view changes reset to page one. File's `prev` still navigates directory history. Auxiliary tables keep their existing display behavior.
- `find "text"` searches the current page snapshot. Pipes work too: `ls | find "text"`, `show | grep -n "text"`, `help | findstr "text"`. Literal, Unicode case-insensitive matching shows source row/line numbers, match counts and yellow highlights. Chain filters for AND matching: `show | find a | find b`. A quoted `|` is literal text.
- Table pipelines search every visible row in the full snapshot, including other pages; result numbers map directly to `detail <n>`. Text pipelines show logical output line numbers. `find` preserves filtering/paging; `filter "text"` changes the view and renumbers rows. Pipes run in-process, without a system shell; supported sources are `show/ls/list/dir/pages/detail/help/search/pwd/version/whoami`.
- `help` groups navigation, display, session and page actions. `help all` lists everything; `help <command>` prefers the current page's usage. Use `run <command>` for a page action that conflicts with a built-in, such as `run show` on Window.
- Gray inline completion previews appear while typing; **Tab** accepts them. Multiple candidates are listed and subsequent Tab presses cycle them. Pipe stages complete `find/grep/findstr`. **Up/Down** recalls session-only history; **Left/Right, Home/End, Delete** edit. **Ctrl+U / Ctrl+W** remove preceding text / the previous word; **Ctrl+L** clears the screen and preserves the draft.
- **Esc / Ctrl+C** cancels input or the entire form. Passwords are masked and excluded from history. Use `exit`, or **Ctrl+D / Ctrl+Z** on an empty line, to leave.
- Tables use measured host display widths and fall back to per-record key/value layout when minimum columns do not fit. Directories have a trailing `/` and distinct color. Settings uses one grouped table. Common UI follows the existing language setting; specialized page fields are not batch-translated. `filter` clears filtering; `detail <row>` shows full fields.
- Non-empty `NO_COLOR` or `AEGISNT_NO_COLOR` disables colors while retaining numbers, counts and `[Tab: candidate]` hints. Non-VT hosts use ASCII layout. Passwords and form fields never receive completion previews or command history.
- The terminal opened from GUI settings runs in a child process and inherits the GUI session. Closing it leaves the main window running.

Examples:

```text
use File
ls "D:\Logs" | find "error"
show | grep -n ".log" | find "2026"
detail 21
show 2
```

Regression checks: `Tests\run_terminal_tests.cmd`; after a Release x64 build, run `python -X utf8 Tests/terminal_smoke.py`, `python -X utf8 Tests/terminal_display_smoke.py`, then `python -X utf8 Tests/terminal_modern_smoke.py`. They cover real File/Settings/ServiceManager/Network displays, independent input and login timeout, snapshot pagination, pipelines, completion, passwords, and English/Chinese 40/80/120-column, no-color and ASCII modes. The last suite saves real native-window screenshots and results in `out/terminal-modern/`. Tests use isolated configuration under `out/terminal-regression/app/` and synthetic fixtures, without drivers or real accounts.

No-argument GUI startup regression: `python -X utf8 Tests/gui_startup_smoke.py` verifies that the app creates native windows and remains alive for at least five seconds without `--console`, using the isolated configuration.

A typical runtime layout is shown below. Some directories and files are deployed or created only when their features are used.

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

HTTPS inspection uses `Data/CA_CERT.pem` and `Data/CA_KEY.pem` and requires the inspected client to trust the corresponding certificate. These prerequisites do not imply that every target application can be decrypted and inspected.

## Building from source

### Desktop application and driver

Check the toolchain and paths used by the project files:

| Item | Current project configuration |
| --- | --- |
| C++ | C++20, x64 |
| MSVC | `PlatformToolset=v145` |
| Qt | `6.7.3/msvc2022_64`; Core, Gui, Widgets, Network |
| Qt build integration | Qt VS Tools / Qt MSBuild |
| UI libraries | QFluent, QWindowKit |
| Cryptography / HTTP inspection | OpenSSL x64 |
| Driver | WDK, `WindowsKernelModeDriver10.0`; target SDK `10.0.28000.0` |

These values describe the current project configuration, not a compatibility matrix. Changing the toolchain requires corresponding changes to project properties, the Qt kit, third-party libraries, and driver build settings.

1. Install the matching MSVC toolchain, Windows SDK / WDK, Qt, and third-party dependencies.
2. Update local paths in [AegisNT.vcxproj](AegisNT.vcxproj), including Qt, Qt MSBuild, QFluent, the QWindowKit property sheet, and OpenSSL include / library and deployment paths. The project currently contains absolute paths such as `D:\Qt\6.7.3\msvc2022_64` and `D:\OpenSSL-Win64`.
3. Open [AegisNT.slnx](AegisNT.slnx) using Visual Studio / MSBuild with `.slnx` support and select `Release | x64`.
4. Build `AegisNT`, `Ring0Core`, `LicenseServer`, and the modules you need. The desktop application is written to `Bin/`; the driver's Release x64 output is `Bin/Drivers/`.
5. For Process monitoring, build `Platform/HookDLL/HookDLL.vcxproj` separately and deploy `MonitorHook.dll` to `Bin/ExtraDLL/`. This project is not included in the main solution.
6. Deploy the required Qt plugins and third-party runtime libraries, then configure the account service as described in “First run.”

To build the full solution:

```powershell
# Run from a Developer PowerShell initialized for the matching MSVC toolchain
msbuild AegisNT.slnx /m /p:Configuration=Release /p:Platform=x64
```

The full solution also references servers and independent modules; their sources and dependencies must be present. To build only the desktop project from the repository root:

```powershell
msbuild AegisNT.vcxproj /m /p:Configuration=Release /p:Platform=x64 /p:OutDir=Bin\
```

> The current `.gitignore` excludes directories including `Drivers/`, `ModulesProject/`, `Server/`, `LicenseServer/`, and `Tests/`. Their presence in the local workspace does not mean a Git checkout contains them. Confirm that all required sources are available. The root-level `build_ui.cmd` and `build_driver_full.cmd` also contain machine-specific paths and need local adjustment.

### Standalone servers

The root [CMakeLists.txt](CMakeLists.txt) **builds only the chat and account servers**, not the Qt client or kernel driver.

It requires CMake 3.20+ and a C++20 toolchain. The account server additionally requires OpenSSL, SQLite3, `cpp-httplib`, and `nlohmann/json`; install them and make them discoverable by CMake first.

```sh
cmake -S . -B build-server
cmake --build build-server --config Release
```

Build only one server by disabling the other:

```sh
# Account server only
cmake -S . -B build-license -DAEGISNT_BUILD_CHAT_SERVER=OFF
cmake --build build-license --config Release --target LicenseServer

# Chat server only
cmake -S . -B build-chat -DAEGISNT_BUILD_LICENSE_SERVER=OFF
cmake --build build-chat --config Release --target Server
```

| Server | Default listener | Client configuration |
| --- | --- | --- |
| `LicenseServer` | `0.0.0.0:8888`, HTTP | `LicenseServer.Address` |
| `Server` | `0.0.0.0:1145`, TCP | `Chat.ServerIP`, `Chat.ServerPort` |

Executable locations depend on the CMake generator; multi-configuration generators typically use a `Release/` subdirectory. `LicenseServer` stores `LicenseServer.db` in its working directory. Update information uses `UpdateConfig.json`, which CMake copies into the build directory.

## Configuration and extensions

[Data/Config.json](Data/Config.json) is the configuration template. At runtime, the application reads and writes `Data/Config.json` beside the executable. The build copies the template only when the destination does not exist, preserving existing runtime settings.

| Section | Main settings |
| --- | --- |
| `Application` | Language, window dimensions, opacity, and related settings |
| `Theme` | Light / dark mode, colors, wallpaper, materials, fonts, and density |
| `Drivers` | Search directories in `Paths` and automatic loading via `AutoLoad` |
| `Modules` | Search directories in `Paths` and automatic loading via `AutoLoad` |
| `LicenseServer` | Account service address |
| `Chat` | Chat server address, port, and username |
| `Payload` / `PayloadShell` | Payload options and session connection settings |

Relative module and driver paths are resolved against the executable directory. Scanning examines files directly inside each configured directory; add any additional subdirectories to `Paths`.

To create a DLL module, refer to [ModuleBase.h](Module/ModuleBase.h) and the existing module projects:

1. Derive from `ModuleBase`, implement `Info()` and `Run()`, and override `Check()` when needed.
2. Register parameters with `RegisterOption()` and export `CreateModule` / `DestroyModule`.
3. Provide `StopModule` following the existing convention for long-running tasks that support cancellation.
4. Use a compatible x64 compiler, runtime library, and interface definition, then deploy the DLL and its dependencies to a configured module directory.

[ModuleTemplate.cpp](ModuleTemplate.cpp) is an incomplete structural draft and requires changes before it can compile.

## Source layout

```text
AegisNT.cpp                 Application entry point, page assembly, and navigation
AegisNT.vcxproj             Qt desktop project
AegisNT.slnx                Desktop, driver, server, and module solution
CMakeLists.txt              Cross-platform server builds
Source/
├── AppContext.*            Shared application state
├── Auth/                   Authentication and credential handling
├── Core/                   Configuration, themes, modules, and session runtime
├── Dialogs/                Login and registration
├── Pages/                  Feature pages
└── KernelResearch.h        Symbol service and kernel research helpers
Platform/                   Driver communication, system APIs, injection, monitoring
Drivers/Ring0Core/           Unified driver and communication protocols
Module/                     Module base class, options, and output capture
ModulesProject/             Independent module projects
Server/                     TCP chat server
LicenseServer/              HTTP account server
Data/                       Default configuration, language resources, certificate files
Installer/                  Inno Setup installer
Tests/                      Focused tests and regression fixtures
External/                   Third-party and supporting code
Bin/                        Desktop Release output and runtime resources
```

Desktop pages and several runtime implementations are included into `AegisNT.cpp` using `#include`. The driver similarly assembles its implementation through `Driver.cpp`. Preserve this organization when editing project files to avoid compiling included implementation files twice.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Login fails and the main window does not open | Account service status, `LicenseServer.Address`, port reachability, and account credentials |
| Missing Qt MSBuild or `QMAKE_CXX.COMPILER_MACROS` / `QMAKE_MSC_VER` errors | Qt MSBuild paths, the initialized MSVC environment, and Qt kit / toolchain compatibility |
| Missing DLL or Qt plugin at startup | Qt, QFluent, QWindowKit, OpenSSL, and platform / TLS plugin deployment |
| Kernel queries fail or show unavailable | Administrator privileges, driver service state, driver loading requirements, Windows build, and matching client / driver protocols |
| Process monitoring fails | Presence of `ExtraDLL/MonitorHook.dll`, target architecture, and the selected injection method |
| Network / HTTP(S) capture fails | WinDivert DLL, driver status, and proxy port; HTTPS also needs certificate configuration; the two capture modes cannot run simultaneously |
| Modules do not appear | Configured paths, DLL dependencies, exports, and ABI compatibility; scanning is not recursive |

## Experimental features and operating limits

Forceful process / handle operations, kernel writes, callback removal, hooks, disk protection, and DSE / PatchGuard controls can affect system stability. Use them only on authorized systems and validate them in a recoverable test environment first.

The PatchGuard implementation includes early bugcheck interception, KPRCB context handling, and DPC handling, with resolution stages, status, and counters exposed in the interface. **An available control does not guarantee effectiveness on every Windows build or prevent bugchecks.** Memory rollback covers only the last write retained by the current page, not an entire session or recovery across restarts.

Client and driver IOCTLs and structure layouts must remain synchronized; update them together. Manage HTTPS inspection keys, account credentials, and server signing configuration separately for each deployment instead of distributing development configuration.

## Packaging and licensing

`Installer/AegisNT.iss` provides an Inno Setup installer with optional VC++ Runtime, Npcap, and HTTP inspection certificate installation. Adjust `SourceDir`, `DepDir`, dependency files, and certificate settings before packaging.

The repository currently has no project-level `LICENSE` file. Project usage terms need to be specified by the maintainer; third-party components retain their own licenses.
