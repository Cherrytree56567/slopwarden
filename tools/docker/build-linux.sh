#!/bin/sh
# Builds ClientWarden for Linux inside the clientwarden-linux image. Run from the repo root:
#   docker run --rm -v "$PWD":/src -v cw-conan:/root/.conan2 -v cw-cargo:/root/.cargo/registry \
#       clientwarden-linux /src/tools/docker/build-linux.sh
# Output: build/linux/app/{clientwarden,libclientwarden.so}
set -e
OUT=/src/build/linux
# The Conan cache is usually a mounted volume, which hides the image's profiles.
conan profile detect --exist-ok >/dev/null
conan install /src -of $OUT --build=missing -s compiler.cppstd=20
cmake -S /src -B $OUT -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=$OUT/build/Release/generators/conan_toolchain.cmake
cmake --build $OUT
