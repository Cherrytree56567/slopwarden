cmake_minimum_required(VERSION 3.16)

project(ClientWarden.Tests LANGUAGES CXX VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

Include(FetchContent)

# From Catch2 Docs
# https://github.com/catchorg/Catch2
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.15.3 # or a later release
)

FetchContent_Declare(
    keychain
    GIT_REPOSITORY https://github.com/Cherrytree56567/keychain
    GIT_TAG master
)

FetchContent_MakeAvailable(Catch2)
FetchContent_MakeAvailable(keychain)

find_package(spdlog CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS url)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Botan CONFIG REQUIRED)
find_package(msgpack-cxx CONFIG REQUIRED)

add_subdirectory(../src/core core)

# One test file per core class, mirroring src/core (tests/core/vault/crypto/crypto.cpp, ...).
file(GLOB_RECURSE CORE_TESTS CONFIGURE_DEPENDS core/*.cpp support/*.cpp)

add_executable(core_tests main.cpp ${CORE_TESTS})
target_link_libraries(core_tests PRIVATE Catch2::Catch2WithMain clientwarden_core)
target_include_directories(core_tests PRIVATE .)

if (APPLE)
    add_custom_command(TARGET core_tests POST_BUILD
        COMMAND codesign --force --deep --sign - $<TARGET_FILE:core_tests>
        COMMENT "Sign Bin to prevent failure"
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(core_tests)

# ADR 3: no std::string in the vault core outside the allowlisted library boundaries.
add_test(NAME lint.no_std_string
    COMMAND ${CMAKE_COMMAND} -DCORE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../src/core -P ${CMAKE_CURRENT_SOURCE_DIR}/lint/no_std_string.cmake)
