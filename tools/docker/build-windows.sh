#!/bin/sh
# Cross-builds ClientWarden for Windows (x86_64, MinGW) inside the clientwarden-windows image:
#   docker run --rm --platform linux/amd64 -v "$PWD":/src -v cw-conan-win:/root/.conan2 \
#       -v cw-cargo-win:/root/.cargo/registry clientwarden-windows /src/tools/docker/build-windows.sh [target]
# Output: build/windows/app/{ClientWarden.exe,libclientwarden.dll}
set -e
OUT=/src/build/windows
# The Conan cache is usually a mounted volume, which hides the image's profiles.
conan profile detect --exist-ok >/dev/null
conan install /src -of $OUT -pr:h /src/tools/docker/conan-windows-mingw -pr:b default --build=missing
cmake -S /src -B $OUT -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$OUT/build/Release/generators/conan_toolchain.cmake \
    -DCW_CARGO_TARGET=x86_64-pc-windows-gnu
cmake --build $OUT ${1:+--target $1}
