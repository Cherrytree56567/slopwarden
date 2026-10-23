# Shared by the console builds (Wii, 3DS): the core's dependencies, prebuilt in the console's
# Docker image under $CONSOLE_DEPS, and the shared UI and platform code in this folder.
#
# Before including: set REPO (the repository root). Then call cw_console_app(<target>).

set(CLIENTWARDEN_CONSOLE ON)
set(CONSOLE_DEPS $ENV{CONSOLE_DEPS})

# The core's dependencies, prebuilt in the image, under the names the core links against.
add_library(botan::botan STATIC IMPORTED)
set_target_properties(botan::botan PROPERTIES IMPORTED_LOCATION ${CONSOLE_DEPS}/lib/libbotan-3.a
    INTERFACE_INCLUDE_DIRECTORIES ${CONSOLE_DEPS}/include/botan-3)
add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
set_target_properties(nlohmann_json::nlohmann_json PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CONSOLE_DEPS}/include)
add_library(spdlog::spdlog INTERFACE IMPORTED)
# newlib's struct tm has no tm_gmtoff, and the consoles have no time zone database anyway.
set_target_properties(spdlog::spdlog PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CONSOLE_DEPS}/include
    INTERFACE_COMPILE_DEFINITIONS SPDLOG_NO_TZ_OFFSET)
add_library(msgpack-cxx INTERFACE IMPORTED)
set_target_properties(msgpack-cxx PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CONSOLE_DEPS}/include
    INTERFACE_COMPILE_DEFINITIONS MSGPACK_NO_BOOST)
add_library(Boost::boost INTERFACE IMPORTED)
set_target_properties(Boost::boost PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CONSOLE_DEPS}/include)
file(GLOB_RECURSE BOOST_URL_SOURCES ${CONSOLE_DEPS}/src/boost_url/*.cpp)
add_library(boost_url STATIC ${BOOST_URL_SOURCES})
target_link_libraries(boost_url PUBLIC Boost::boost)
target_compile_definitions(boost_url PUBLIC BOOST_URL_STATIC_LINK BOOST_URL_NO_LIB)
add_library(Boost::url ALIAS boost_url)

add_subdirectory(${REPO}/src/core ${CMAKE_BINARY_DIR}/core)

# mbedTLS for HTTPS; the app supplies its entropy and millisecond clock.
add_library(mbedtls_all INTERFACE)
target_include_directories(mbedtls_all INTERFACE ${CONSOLE_DEPS}/include)
target_link_libraries(mbedtls_all INTERFACE ${CONSOLE_DEPS}/lib/libmbedtls.a ${CONSOLE_DEPS}/lib/libmbedx509.a
    ${CONSOLE_DEPS}/lib/libmbedcrypto.a ${CONSOLE_DEPS}/lib/libeverest.a ${CONSOLE_DEPS}/lib/libp256m.a)

# Test builds (-DCLIENTWARDEN_CONSOLE_TEST_BUILD=ON) add the emulator script runner and the
# randomness override; release builds never contain them.
option(CLIENTWARDEN_CONSOLE_TEST_BUILD "Build for automated testing in an emulator (insecure)" OFF)

function(cw_console_app _target)
    file(GLOB CONSOLE_SOURCES CONFIGURE_DEPENDS ${REPO}/src/Platforms/Shared/Console/*.cpp)
    target_sources(${_target} PRIVATE ${CONSOLE_SOURCES}
        ${REPO}/src/Platforms/Shared/JsonBridge/JsonBridge.cpp
        ${REPO}/src/Platforms/Shared/JsonBridge/JsonBridgeShared.cpp)
    target_include_directories(${_target} PRIVATE ${REPO}/src/Platforms/Shared
        ${REPO}/src/Platforms/Shared/Console)
    target_link_libraries(${_target} PRIVATE clientwarden_core_runtime mbedtls_all)
    # std::thread gets a tiny default stack; thread_stack.cpp gives it a real one.
    target_link_options(${_target} PRIVATE -Wl,--wrap=pthread_create)
    # UTC correction for the console clock (Shared/Console/utc.cpp).
    target_link_options(${_target} PRIVATE -Wl,--wrap=__syscall_gettod_r -Wl,--wrap=__syscall_clock_gettime)
    if (CLIENTWARDEN_CONSOLE_TEST_BUILD)
        target_compile_definitions(${_target} PRIVATE CLIENTWARDEN_CONSOLE_TEST_BUILD)
    endif()
endfunction()
