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

# The whole vault core except the production wiring (real network and
# singleton), which tests replace with fakes.
file(GLOB_RECURSE VAULT_SOURCES CONFIGURE_DEPENDS ../src/Vault/*.cpp)
list(FILTER VAULT_SOURCES EXCLUDE REGEX ".*/(HttplibTransport|VaultInstance)\\.cpp$")

add_executable(tests
    test.cpp
    crypto/crypto.cpp
    crypto/generator.cpp
    model/item.cpp
    model/query.cpp
    sync/merge.cpp
    net/api.cpp
    net/notifications.cpp
    vault/vault.cpp
    utils/utils.cpp
    Storage/Storage.cpp
    Clipboard/Clipboard.cpp
    ${VAULT_SOURCES}
)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain spdlog::spdlog Boost::boost Boost::url nlohmann_json::nlohmann_json botan::botan msgpack-cxx keychain)

if(APPLE)
    set_target_properties(tests PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "-"
        XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "YES"
        XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "YES"
    )
endif()

target_include_directories(tests PRIVATE
    ../src/Vault
    .
)

target_compile_definitions(tests PRIVATE MSGPACK_DISABLE_LEGACY_NIL)

if (APPLE)
    add_custom_command(TARGET tests POST_BUILD
        COMMAND codesign --force --deep --sign - $<TARGET_FILE:tests>
        COMMENT "Sign Bin to prevent failure"
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(tests)
