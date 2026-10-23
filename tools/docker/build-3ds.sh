#!/bin/sh
# Builds ClientWarden for the 3DS inside the clientwarden-3ds image. From the repo root:
#   docker run --rm -v "$PWD":/src clientwarden-3ds /src/tools/docker/build-3ds.sh [cmake args]
# Output: build/3ds/3ds/clientwarden (copy the 3ds/ folder to the root of an SD card).
set -e
OUT=/src/build/3ds
cmake -S /src/src/Platforms/3DS -B $OUT/cmake -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/3DS.cmake "$@"
cmake --build $OUT/cmake -j8
