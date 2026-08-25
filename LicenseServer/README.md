# Cross-platform license server

The HTTP license server supports Windows and Linux. It requires OpenSSL,
SQLite3, `cpp-httplib`, and `nlohmann/json` development packages.

On Debian/Ubuntu, the required system packages are typically `libssl-dev`,
`libsqlite3-dev`, `nlohmann-json3-dev`, and `libcpp-httplib-dev`.

Build it from the repository root with:

```sh
cmake -S . -B build -DAEGISNT_BUILD_CHAT_SERVER=OFF
cmake --build build --config Release --target LicenseServer
```

The server listens on HTTP port `8888` and stores `LicenseServer.db` in its
working directory.
