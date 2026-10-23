# ClientWarden for the Nintendo Wii. Configure with devkitPro's toolchain inside the
# clientwarden-wii image (tools/docker/wii.Dockerfile); see tools/docker/build-wii.sh.
cmake_minimum_required(VERSION 3.22)
project(ClientWardenWii C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CLIENTWARDEN_WII ON)
set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(WII_DEPS $ENV{WII_DEPS})

# The core's dependencies, prebuilt in the image, under the names the core links against.
add_library(botan::botan STATIC IMPORTED)
set_target_properties(botan::botan PROPERTIES IMPORTED_LOCATION ${WII_DEPS}/lib/libbotan-3.a
    INTERFACE_INCLUDE_DIRECTORIES ${WII_DEPS}/include/botan-3)
add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
set_target_properties(nlohmann_json::nlohmann_json PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${WII_DEPS}/include)
add_library(spdlog::spdlog INTERFACE IMPORTED)
# newlib's struct tm has no tm_gmtoff, and the Wii has no time zone database anyway.
set_target_properties(spdlog::spdlog PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${WII_DEPS}/include
    INTERFACE_COMPILE_DEFINITIONS SPDLOG_NO_TZ_OFFSET)
add_library(msgpack-cxx INTERFACE IMPORTED)
set_target_properties(msgpack-cxx PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${WII_DEPS}/include
    INTERFACE_COMPILE_DEFINITIONS MSGPACK_NO_BOOST)
add_library(Boost::boost INTERFACE IMPORTED)
set_target_properties(Boost::boost PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${WII_DEPS}/include)
file(GLOB_RECURSE BOOST_URL_SOURCES ${WII_DEPS}/src/boost_url/*.cpp)
add_library(boost_url STATIC ${BOOST_URL_SOURCES})
target_link_libraries(boost_url PUBLIC Boost::boost)
target_compile_definitions(boost_url PUBLIC BOOST_URL_STATIC_LINK BOOST_URL_NO_LIB)
add_library(Boost::url ALIAS boost_url)

add_subdirectory(${REPO}/src/core core)

# mbedTLS for HTTPS; the app supplies its entropy and millisecond clock.
add_library(mbedtls_all INTERFACE)
target_include_directories(mbedtls_all INTERFACE ${WII_DEPS}/include)
target_link_libraries(mbedtls_all INTERFACE ${WII_DEPS}/lib/libmbedtls.a ${WII_DEPS}/lib/libmbedx509.a
    ${WII_DEPS}/lib/libmbedcrypto.a ${WII_DEPS}/lib/libeverest.a ${WII_DEPS}/lib/libp256m.a)

# Test builds (-DCLIENTWARDEN_WII_TEST_BUILD=ON) add the Dolphin script runner and the
# entropy override; release builds never contain them.
option(CLIENTWARDEN_WII_TEST_BUILD "Build for automated testing in Dolphin (insecure)" OFF)

file(GLOB WII_PLATFORM_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Platform/*.cpp)
file(GLOB_RECURSE WII_UI_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/UI/*.cpp)
add_executable(clientwarden ${WII_PLATFORM_SOURCES} ${WII_UI_SOURCES}
    ${REPO}/src/Platforms/Shared/JsonBridge/JsonBridge.cpp
    ${REPO}/src/Platforms/Shared/JsonBridge/JsonBridgeShared.cpp)
target_include_directories(clientwarden PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${REPO}/src/Platforms/Shared)
target_link_libraries(clientwarden PRIVATE clientwarden_core_runtime mbedtls_all)
# std::thread gets libogc's 8 KB default stack; UI/thread_stack.cpp gives it a real one.
target_link_options(clientwarden PRIVATE -Wl,--wrap=pthread_create)
# UTC correction for the console clock (Platform/System.cpp).
target_link_options(clientwarden PRIVATE -Wl,--wrap=__syscall_gettod_r -Wl,--wrap=__syscall_clock_gettime)
if (CLIENTWARDEN_WII_TEST_BUILD)
    target_compile_definitions(clientwarden PRIVATE CLIENTWARDEN_WII_TEST_BUILD)
endif()

# SDL2 (+ttf) from devkitPro's portlibs, then libogc.
find_package(PkgConfig REQUIRED)
pkg_check_modules(WII_SDL REQUIRED IMPORTED_TARGET SDL2_ttf sdl2)
target_link_libraries(clientwarden PRIVATE PkgConfig::WII_SDL)

# The Homebrew Channel layout: apps/clientwarden/{boot.dol,meta.xml,icon.png} plus the
# resources the app reads (word list, CA bundle, font).
set(WII_APP_DIR ${CMAKE_BINARY_DIR}/../apps/clientwarden)
ogc_create_dol(clientwarden)
add_custom_command(TARGET clientwarden POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${WII_APP_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/clientwarden.dol ${WII_APP_DIR}/boot.dol
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/meta.xml ${WII_APP_DIR}/meta.xml
    COMMAND ${CMAKE_COMMAND} -E copy ${REPO}/ClientWarden/clientgen.txt ${WII_APP_DIR}/clientgen.txt
    COMMAND ${CMAKE_COMMAND} -E copy ${WII_DEPS}/share/cacert.pem ${WII_APP_DIR}/cacert.pem
    COMMAND ${CMAKE_COMMAND} -E copy ${WII_DEPS}/share/DejaVuSans.ttf ${WII_APP_DIR}/DejaVuSans.ttf
    COMMAND ${CMAKE_COMMAND} -E copy ${WII_DEPS}/share/DejaVuSans-Bold.ttf ${WII_APP_DIR}/DejaVuSans-Bold.ttf
)
