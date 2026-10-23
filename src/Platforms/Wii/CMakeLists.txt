# ClientWarden for the Nintendo Wii. Configure with devkitPro's toolchain inside the
# clientwarden-wii image (tools/docker/wii.Dockerfile); see tools/docker/build-wii.sh.
cmake_minimum_required(VERSION 3.22)
project(ClientWardenWii C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(WII_DEPS $ENV{CONSOLE_DEPS})

include(${REPO}/src/Platforms/Shared/Console/console.cmake)

file(GLOB WII_PLATFORM_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Platform/*.cpp)
file(GLOB_RECURSE WII_UI_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/UI/*.cpp)
add_executable(clientwarden ${WII_PLATFORM_SOURCES} ${WII_UI_SOURCES})
cw_console_app(clientwarden)
# Platform/ holds console_metrics.h and console_net.h for the shared code.
target_include_directories(clientwarden PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Platform)

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
