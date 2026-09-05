# Cross-platform chat server

The server supports Windows and Linux through the native socket API on each
platform. Build it from the repository root with:

```sh
cmake -S . -B build -DAEGISNT_BUILD_LICENSE_SERVER=OFF
cmake --build build --config Release --target Server
```

It listens on TCP port `1145`.

On Linux, install a C++20 compiler and pthread development support before
running CMake.
