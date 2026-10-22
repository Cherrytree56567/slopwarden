#!/bin/sh
# Builds ClientWarden for Linux inside the clientwarden-linux image. Run from the repo root:
#   docker run --rm -v "$PWD":/src -v cw-conan:/root/.conan2 -v cw-cargo:/root/.cargo/registry \
#       clientwarden-linux /src/tools/docker/build-linux.sh
# Output: build/linux/app/{clientwarden,libclientwarden.so}
set -e
OUT=/src/build/linux
conan install /src -of $OUT --build=missing
cmake -S /src -B $OUT -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$OUT/build/Release/generators/conan_toolchain.cmake
cmake --build $OUT
