# ClientWarden for the Nintendo 3DS. Configure with devkitPro's toolchain inside the
# clientwarden-3ds image (tools/docker/3ds.Dockerfile); see tools/docker/build-3ds.sh.
cmake_minimum_required(VERSION 3.22)
project(ClientWarden3DS C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include(${REPO}/src/Platforms/Shared/Console/console.cmake)

file(GLOB N3DS_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Platform/*.cpp ${CMAKE_CURRENT_SOURCE_DIR}/UI/*.cpp)
add_executable(clientwarden ${N3DS_SOURCES})
cw_console_app(clientwarden)
# Platform/ holds console_metrics.h and console_net.h for the shared code.
target_include_directories(clientwarden PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Platform)

find_package(PkgConfig REQUIRED)
pkg_check_modules(N3DS_FREETYPE REQUIRED IMPORTED_TARGET freetype2)
target_link_libraries(clientwarden PRIVATE PkgConfig::N3DS_FREETYPE)

# The Homebrew Launcher layout: 3ds/clientwarden/{clientwarden.3dsx} plus the resources the
# app reads (word list, CA bundle, fonts).
set(N3DS_APP_DIR ${CMAKE_BINARY_DIR}/../3ds/clientwarden)
ctr_generate_smdh(clientwarden.smdh NAME "ClientWarden" DESCRIPTION "Bitwarden password manager"
    AUTHOR "CT5") # libctru's default icon until the app has one
ctr_create_3dsx(clientwarden SMDH clientwarden.smdh)
add_custom_command(TARGET clientwarden POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${N3DS_APP_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${REPO}/ClientWarden/clientgen.txt ${N3DS_APP_DIR}/clientgen.txt
    COMMAND ${CMAKE_COMMAND} -E copy ${CONSOLE_DEPS}/share/cacert.pem ${N3DS_APP_DIR}/cacert.pem
    COMMAND ${CMAKE_COMMAND} -E copy ${CONSOLE_DEPS}/share/DejaVuSans.ttf ${N3DS_APP_DIR}/DejaVuSans.ttf
    COMMAND ${CMAKE_COMMAND} -E copy ${CONSOLE_DEPS}/share/DejaVuSans-Bold.ttf ${N3DS_APP_DIR}/DejaVuSans-Bold.ttf
)
add_custom_target(clientwarden_app ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/clientwarden.3dsx ${N3DS_APP_DIR}/clientwarden.3dsx
    DEPENDS clientwarden_3dsx)
