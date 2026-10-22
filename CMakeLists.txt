cmake_minimum_required(VERSION 3.22)
project(ClientWarden VERSION 1.0)

message(STATUS "WIN32=${WIN32} APPLE=${APPLE} ANDROID=${ANDROID} LINUX=${LINUX} UNIX=${UNIX}")

if (APPLE)
    enable_language(OBJCXX)
    enable_language(Swift)
endif()

# Mac Specific stuff
set(TEAM_ID "IDABC16767")
set(SHARED_BUNDLE_ID "app.ct5.clientwarden")
set(APP_BUNDLE_ID "com.ct5.clientwarden")

set(CW_IDENTIFIER ${APP_BUNDLE_ID})
set(CW_VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# The core and keychain static libraries end up inside shared libraries (Android, Linux, Windows).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if (APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "Minimum macOS deployment version")
endif()

set(Botan_DIR "build/build/generators")

include(FetchContent)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/Cherrytree56567/keychain
    GIT_TAG master
)

FetchContent_MakeAvailable(keychain)
# Its warnings shouldn't stop our build (keychain_win.cpp has an unused parameter under MinGW).
if (NOT MSVC)
    target_compile_options(keychain PRIVATE -Wno-error)
endif()

find_package(OpenSSL REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)
find_package(msgpack-cxx CONFIG REQUIRED)

get_target_property(JSON_INCLUDES
    nlohmann_json::nlohmann_json
    INTERFACE_INCLUDE_DIRECTORIES
)

message(STATUS "nlohmann_json target: nlohmann_json::nlohmann_json")
message(STATUS "nlohmann_json includes: ${JSON_INCLUDES}")

if (WIN32)
    include(cmake/windows.cmake)
elseif (ANDROID)
    include(cmake/android.cmake)
elseif (LINUX)
    include(cmake/linux.cmake)
elseif (APPLE)
    include(cmake/macos.cmake)
else ()
    message(WARNING "Unknown platform: won't build UI")
endif()

# The platform-independent vault core (src/core); see Wiki/Architecturev2.md.
add_subdirectory(src/core)

if (WIN32)
    add_library(clientwarden SHARED)
elseif (ANDROID)
    add_library(clientwarden SHARED)
elseif (LINUX)
    add_library(clientwarden SHARED)
elseif (APPLE)
    add_executable(clientwarden MACOSX_BUNDLE)
    #add_library(clientwarden SHARED) # Remove comment to use Linux Build on MacOS
else()
    add_library(clientwarden SHARED)
endif()

target_link_libraries(clientwarden PRIVATE clientwarden_core_runtime)

target_include_directories(clientwarden PRIVATE src/Platforms/)

if (ANDROID)
    target_compile_options(clientwarden PRIVATE -fexperimental-library)
    target_link_options(clientwarden PRIVATE -fexperimental-library)
endif()

if (WIN32 OR APPLE OR LINUX OR ANDROID)
    buildUI(clientwarden)
endif()

