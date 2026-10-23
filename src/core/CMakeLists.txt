# The platform-independent vault core (see Wiki/Architecturev2.md).
#
# clientwarden_core          everything testable; no real network, no process singleton
# clientwarden_core_runtime  production wiring: httplib transport and VaultManager::instance()
#
# Callers must provide clientwarden::paths::dataDirectory()/resourceDirectory() (platform code).

file(GLOB_RECURSE CLIENTWARDEN_CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
set(CLIENTWARDEN_CORE_RUNTIME_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/http/httplib_transport.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/vault_manager/vault_manager_instance.cpp
)
set(CLIENTWARDEN_KEYCHAIN_FACTORY ${CMAKE_CURRENT_SOURCE_DIR}/platform/secret_store/keychain_factory.cpp)
list(REMOVE_ITEM CLIENTWARDEN_CORE_SOURCES ${CLIENTWARDEN_CORE_RUNTIME_SOURCES} ${CLIENTWARDEN_KEYCHAIN_FACTORY})

# The consoles (Wii, 3DS) have no keychain or cpp-httplib, and the Wii no OS random generator;
# their platform code (src/Platforms/Shared/Console and Wii/, 3DS/) provides random::secure(),
# the secret store and the HTTP transport.
if (CLIENTWARDEN_CONSOLE)
    list(REMOVE_ITEM CLIENTWARDEN_CORE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/random/random.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/secret_store/keychain_secret_store.cpp
    )
    list(REMOVE_ITEM CLIENTWARDEN_CORE_RUNTIME_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/platform/http/httplib_transport.cpp)
endif()

# Platforms without an OS keychain the keychain library supports define
# createPlatformSecretStore() themselves.
if (NOT ANDROID AND NOT CLIENTWARDEN_CONSOLE)
    list(APPEND CLIENTWARDEN_CORE_RUNTIME_SOURCES ${CLIENTWARDEN_KEYCHAIN_FACTORY})
endif()

add_library(clientwarden_core STATIC ${CLIENTWARDEN_CORE_SOURCES})
target_compile_features(clientwarden_core PUBLIC cxx_std_20)
target_include_directories(clientwarden_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(clientwarden_core PUBLIC MSGPACK_DISABLE_LEGACY_NIL)
target_link_libraries(clientwarden_core PUBLIC
    botan::botan
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    Boost::boost
    Boost::url
    msgpack-cxx
)
if (NOT CLIENTWARDEN_CONSOLE)
    target_link_libraries(clientwarden_core PUBLIC keychain)
endif()

if (CLIENTWARDEN_CONSOLE)
    add_library(clientwarden_core_runtime STATIC ${CLIENTWARDEN_CORE_RUNTIME_SOURCES})
    target_link_libraries(clientwarden_core_runtime PUBLIC clientwarden_core)
elseif (TARGET httplib::httplib)
    add_library(clientwarden_core_runtime STATIC ${CLIENTWARDEN_CORE_RUNTIME_SOURCES})
    target_link_libraries(clientwarden_core_runtime PUBLIC clientwarden_core httplib::httplib OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(clientwarden_core_runtime PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

# NDK r27's libc++ (LLVM 18) keeps std::jthread and std::stop_token behind this flag.
if (ANDROID)
    target_compile_options(clientwarden_core PUBLIC -fexperimental-library)
    target_link_options(clientwarden_core PUBLIC -fexperimental-library)
endif()

# Windows 10 or later (cpp-httplib needs Windows 8+ APIs; MinGW defaults lower).
if (WIN32)
    target_compile_definitions(clientwarden_core PUBLIC _WIN32_WINNT=0x0A00 WINVER=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
