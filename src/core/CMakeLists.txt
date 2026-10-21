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

# Platforms without an OS keychain the keychain library supports define
# createPlatformSecretStore() themselves.
if (NOT ANDROID AND NOT CLIENTWARDEN_WII)
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
    keychain
)

if (TARGET httplib::httplib)
    add_library(clientwarden_core_runtime STATIC ${CLIENTWARDEN_CORE_RUNTIME_SOURCES})
    target_link_libraries(clientwarden_core_runtime PUBLIC clientwarden_core httplib::httplib OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(clientwarden_core_runtime PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
endif()
