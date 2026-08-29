cmake_minimum_required(VERSION 3.20)
project(AegisNTServers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AEGISNT_BUILD_CHAT_SERVER "Build the TCP chat server" ON)
option(AEGISNT_BUILD_LICENSE_SERVER "Build the HTTP license server" ON)

if(AEGISNT_BUILD_CHAT_SERVER)
  add_executable(Server Server/Server.cpp)
  target_include_directories(Server PRIVATE Server)
  if(WIN32)
    target_link_libraries(Server PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(Server PRIVATE Threads::Threads)
  endif()
endif()

if(AEGISNT_BUILD_LICENSE_SERVER)
  find_package(OpenSSL REQUIRED)
  find_package(SQLite3 REQUIRED)

  find_path(HTTPLIB_INCLUDE_DIR httplib.h REQUIRED)
  find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp REQUIRED)

  add_executable(LicenseServer LicenseServer/LicenseServer.cpp)
  configure_file(LicenseServer/UpdateConfig.json
    ${CMAKE_CURRENT_BINARY_DIR}/UpdateConfig.json COPYONLY)
  target_include_directories(LicenseServer PRIVATE
    LicenseServer
    ${HTTPLIB_INCLUDE_DIR}
    ${NLOHMANN_JSON_INCLUDE_DIR}
  )
  target_link_libraries(LicenseServer PRIVATE
    OpenSSL::Crypto
    SQLite::SQLite3
  )
  if(WIN32)
    target_link_libraries(LicenseServer PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(LicenseServer PRIVATE Threads::Threads dl)
  endif()
endif()
