# AegisNT

[中文](README.md) | [English](README_EN.md)

AegisNT is a Windows x64 system inspection, process management, and kernel debugging tool. The desktop application is built with C++20, Qt 6, and QFluent. Its `MultiDrv` and `MonitorDrv` drivers provide inspection, protection, and system operations that are unavailable through user-mode APIs alone.

> This project includes privileged operations such as process termination, handle closure, memory access, driver loading, DLL injection, and security policy changes. Use it only on systems you own or are explicitly authorized to test. Incorrect use may crash applications, destabilize Windows, or cause a bug check.

## Features

- **System and task management**: Inspect processes, threads, tokens, modules, memory, PEB data, handles, and mitigation policies with live updates.
- **Process operations**: Terminate, suspend, resume, configure PPL or critical-process state, manipulate tokens, inject DLLs, and manage protection rules.
- **Handle management**: Includes the system-wide `HandleLab` page for handle triage by process, type, object, and risk, with close, duplicate, and downgrade actions.
- **System monitoring**: Capture process, thread, image, registry, file, and network events.
- **Registry and file tools**: Browse, edit, monitor, and configure protection rules.
- **Window management**: Enumerate windows, change window state, and configure driver-backed window protection.
- **Driver and kernel inspection**: Manage driver services and inspect kernel modules, objects, callbacks, MiniFilters, WFP, NDIS, security state, and system tables.
- **Driver object inspection**: Driver Inspector shows IRP major functions, Fast I/O dispatch, DeviceObject/AttachedDevice/NextDevice chains, and symbol ownership for function addresses.
- **Kernel analysis views**: `KernelInspector` covers filters, networking, security state, synchronization objects, sessions, and related kernel inspection workflows.
- **Kernel research center**: resolves kernel address ownership through the Microsoft public symbol cache and adds integrity baselines, Big Pool aggregation, and object namespace browsing.
- **Memory tools**: Read, write, and inspect process memory through user-mode APIs or `MultiDrv`.
- **Transactional kernel writes**: executes staged writes immediately while silently preserving original bytes, verifies by reading back, restores failed writes, supports session rollback, and records JSONL audit events.
- **Module system**: Load independent feature modules. The repository includes ARP, HTTP/2, and payload-related example projects.
- **Customizable UI**: QFluent-based interface with configurable theme colors, backgrounds, font scaling, density, and window opacity.

When a driver is unavailable, supported queries fall back to Windows user-mode APIs. Operations that require kernel access remain unavailable and report their status.

## Repository Layout

```text
.
|-- AegisNT.cpp             # Qt application and page implementations
|-- AegisNT.vcxproj         # Visual Studio application project
|-- AegisNT.slnx            # Application, driver, and module solution
|-- Platform/               # Driver communication, injection, and platform APIs
|-- Drivers/
|   |-- MultiDrv/           # Kernel inspection, protection, and system operations
|   `-- MonitorDrv/         # System, file, and network event monitoring
|-- Module/                 # Module ABI, loader, and output capture
|-- ModulesProject/         # Independent module projects
|-- Data/                   # Default configuration, icons, and runtime data
|-- Bin/                    # Release output and runtime dependencies
|-- Installer/              # Inno Setup installer
`-- External/               # Third-party and supporting code
```

## Navigation Layout

The desktop navigation is currently organized as follows:

- **Information / Task / Monitor / Registry / File / Window**: core system pages and user-mode tooling
- **Kernel / Overview**: `KernelInspector`
- **Kernel / Research**: `KernelResearch` (`Symbols`, `Address Ownership`, `Integrity`, `Big Pool`, `Objects`)
- **Kernel / Execution**: `Driver`, `ServiceManager`, `HandleLab`, `Memory`, `Table`, `Callback`
- **Kernel / Storage**: `Disk`
- **Module**: `Payload`, `ModuleRun`, `ModuleManager`
- **Console / Settings**: debugging console, theme, language, and path configuration

## Requirements

- Windows 10 or Windows 11 x64
- Visual Studio 2022 or a compatible MSVC x64 toolchain
- Windows 10/11 SDK
- Qt 6.7.x with at least `Core`, `Gui`, `Widgets`, and `Network`
- Qt VS Tools / Qt MSBuild
- QFluent
- QWindowKit
- OpenSSL x64
- Windows Driver Kit for building the drivers
- Inno Setup 6, optional, for creating the installer

The project currently contains developer-machine absolute paths, including:

```text
D:\Qt\6.7.3\msvc2022_64
D:\OpenSSL-Win64
```

Before the first build, update the Qt, QFluent, QWindowKit, and OpenSSL include, library, and DLL paths in `AegisNT.vcxproj` or in the Visual Studio project properties. Property sheets or environment variables are recommended to avoid committing machine-specific paths.

## Building

1. Install the dependencies and register the MSVC Qt kit in Qt VS Tools.
2. Open `AegisNT.slnx` in Visual Studio.
3. Select the `x64` and `Release` configuration.
4. Build `MultiDrv`, `MonitorDrv`, and any required modules before building `AegisNT`.
5. The Release application is written to `Bin/`.

You can also build from a terminal with an initialized MSVC environment:

```powershell
msbuild AegisNT.slnx /m /p:Configuration=Release /p:Platform=x64
```

If the build reports:

```text
QMAKE_CXX.COMPILER_MACROS is not defined
QMAKE_MSC_VER isn't set
```

run the command from the matching Visual Studio Developer PowerShell or Command Prompt, then verify that the Qt kit matches the selected MSVC toolset.

## Running and Drivers

Run the application as an administrator:

```powershell
.\Bin\AegisNT.exe
```

Kernel features require `MultiDrv`, while monitoring features require `MonitorDrv`. Drivers must match the system architecture and carry a signature accepted by Windows. Use test-signing configurations only on isolated development machines or virtual machines.

Create and start the driver services using the actual `.sys` paths:

```powershell
sc.exe create MultiDrv type= kernel binPath= "C:\path\to\MultiDrv.sys"
sc.exe start MultiDrv

sc.exe create MonitorDrv type= kernel binPath= "C:\path\to\MonitorDrv.sys"
sc.exe start MonitorDrv
```

Stop the services with:

```powershell
sc.exe stop MonitorDrv
sc.exe stop MultiDrv
```

If a device cannot be opened, check administrator privileges, service state, driver signing, Windows event logs, and whether the application and driver communication structures came from the same build.

## Configuration and Modules

The default configuration is stored in `Data/Config.json`. Runtime resources and modules are normally loaded from `Bin/Data`, `Bin/Drivers`, `Bin/Modules`, and `Bin/ExtraDLL`. Do not commit local configurations containing private keys, tokens, target addresses, or other sensitive data.

Modules use the interfaces defined under `Module/`. New modules must preserve ABI compatibility and deploy their DLLs and dependencies to the appropriate directory under `Bin/Modules`. Projects under `ModulesProject/` provide implementation examples.

## Installer

`Installer/AegisNT.iss` packages the application with Inno Setup and can optionally install the VC++ Runtime, Npcap, and an HTTP inspection certificate. Before generating an installer, update `SourceDir` and `DepDir` at the top of the script and verify the certificate subject and thumbprint.

Do not distribute the development certificate private key included in the repository. Production releases should use a separately generated certificate with securely stored private keys and updated installer metadata.

## Security Notes

- Test drivers, injection, DSE changes, callback removal, and kernel memory operations in a virtual machine first.
- Create a snapshot before operating on critical processes, system handles, or unknown kernel addresses.
- User-mode fallback results may be limited by privileges, PPL, and the Windows version, and may differ from the kernel view.
- Driver IOCTLs, structure sizes, and versions must remain synchronized with `Platform/MultiDrvCall.h`.
- Network and payload modules are intended only for authorized testing and defensive research.

## License

The repository currently has no license file. Until an explicit `LICENSE` is added, all rights are reserved and no permission to copy, modify, or redistribute the code should be assumed.
