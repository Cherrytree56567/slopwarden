#!/bin/sh
# Builds ClientWarden for the Wii inside the clientwarden-wii image. From the repo root:
#   docker run --rm -v "$PWD":/src clientwarden-wii /src/tools/docker/build-wii.sh [target]
# Output: build/wii/apps/clientwarden (copy apps/ to the root of an SD card).
set -e
OUT=/src/build/wii
cmake -S /src/src/Platforms/Wii -B $OUT/cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/Wii.cmake
cmake --build $OUT/cmake -j8 ${1:+--target $1}
