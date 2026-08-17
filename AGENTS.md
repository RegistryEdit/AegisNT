# Repository Guidelines

## Project Structure & Module Organization

`AegisNT.cpp` is the Qt desktop application entry point. Shared application code
lives in `Source/`, with page factories and page implementations under
`Source/Pages/`. Windows platform wrappers, driver communication, and injection
helpers are in `Platform/`. Kernel drivers are separate WDK projects in
`Drivers/`; keep user-mode IOCTL structures synchronized with their driver
counterparts. `Module/` defines the module ABI, while `ModulesProject/` contains
independent module implementations. Runtime assets and configuration belong in
`Data/`, release artifacts in `Bin/`, and Inno Setup packaging in `Installer/`.

## Build, Test, and Development Commands

Open `AegisNT.slnx` in Visual Studio 2022, select `Release|x64`, and build the
required drivers before the application. From a Visual Studio Developer
PowerShell, run:

```powershell
msbuild AegisNT.slnx /m /p:Configuration=Release /p:Platform=x64
```

This environment is required so Qt/qmake can discover MSVC. Run the application
as administrator with `./Bin/AegisNT.exe`. Driver-backed features require the
matching signed `MultiDrv` and `MonitorDrv` binaries to be installed and running.

## Coding Style & Naming Conventions

Use C++20 and existing Qt/QFluent patterns. Indent with two spaces; place braces
on the declaration line; use PascalCase for types and functions, and descriptive
factory names such as `CreateMonitorPage`. Keep page declarations in matching
`.h` files and implementations in `.cpp` files. Prefer focused changes and do
not introduce machine-specific SDK, Qt, or OpenSSL paths into tracked files.

## Testing Guidelines

There is no dedicated unit-test suite. Every change requires a `Release|x64`
build and a targeted manual smoke test of the affected UI or module. For driver
changes, verify the matching user-mode request, structure layout, IOCTL behavior,
and rollback/error path on an isolated test system. Validate module loading from
`Bin/Modules` when modifying the module ABI or deployment layout.

## Commit & Pull Request Guidelines

Use concise imperative commits, following the existing release style where
appropriate: `v3.5.0` or `Update AegisNT.iss`. Keep each commit scoped to one
change. Pull requests should summarize behavior, list build and smoke-test
results, link related issues, and include screenshots for UI changes. Do not
commit private keys, certificates, tokens, local `Data/Config.json` values, or
developer-machine paths.
