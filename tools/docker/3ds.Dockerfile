# 3DS build environment: devkitARM + libctru + FreeType, plus the core's dependencies built
# for the 3DS (ARM11 MPCore, armv6k, newlib):
#   docker build -t clientwarden-3ds -f tools/docker/3ds.Dockerfile tools/docker
FROM devkitpro/devkitarm:latest

RUN apt-get update && apt-get install -y --no-install-recommends python3 xz-utils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV CONSOLE_DEPS=/opt/3ds-deps
ARG MACHDEP="-D__3DS__ -march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft -mword-relocations -ffunction-sections"
WORKDIR /tmp/deps

# mbedTLS for TLS: no sockets or OS entropy of its own, the app supplies both.
RUN curl -sSL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2 | tar xj \
    && cd mbedtls-3.6.5 \
    && python3 scripts/config.py unset MBEDTLS_NET_C \
    && python3 scripts/config.py unset MBEDTLS_TIMING_C \
    && python3 scripts/config.py unset MBEDTLS_FS_IO \
    && python3 scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C \
    && python3 scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C \
    && python3 scripts/config.py set MBEDTLS_NO_PLATFORM_ENTROPY \
    && python3 scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG \
    && python3 scripts/config.py set MBEDTLS_PLATFORM_MS_TIME_ALT \
    && cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/3DS.cmake -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=$CONSOLE_DEPS \
    && cmake --build build -j8 && cmake --install build && cd .. && rm -rf mbedtls-3.6.5

# Botan with just what the core uses (and ChaCha_RNG for the Wii's own generator).
RUN curl -sSL https://botan.randombit.net/releases/Botan-3.11.1.tar.xz | tar xJ \
    && cd Botan-3.11.1 \
    && python3 configure.py --os=none --cpu=arm32 --cc=gcc --cc-bin=$DEVKITARM/bin/arm-none-eabi-g++ \
        --ar-command=$DEVKITARM/bin/arm-none-eabi-ar --cxxflags="$MACHDEP -O2" \
        --build-targets=static --without-documentation --prefix=$CONSOLE_DEPS --minimized-build \
        --enable-modules=aes,cbc,hmac,sha1,sha2_32,sha2_64,hkdf,pbkdf2,argon2,rsa,eme_oaep,eme_pkcs1,emsa_pkcs1,x509,pubkey,base32,base64,hex,hotp,chacha_rng,hmac_drbg,pbes2,pem \
    && make -j8 && make install && cd .. && rm -rf Botan-3.11.1

# Header-only: nlohmann/json, spdlog (bundled fmt), msgpack-cxx; Boost headers (Boost.URL's
# sources are compiled into the app).
RUN mkdir -p $CONSOLE_DEPS/include/nlohmann \
    && curl -sSL -o $CONSOLE_DEPS/include/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp \
    && curl -sSL https://github.com/gabime/spdlog/archive/refs/tags/v1.17.0.tar.gz | tar xz \
    && cp -r spdlog-1.17.0/include/spdlog $CONSOLE_DEPS/include/ && rm -rf spdlog-1.17.0 \
    && curl -sSL https://github.com/msgpack/msgpack-c/releases/download/cpp-7.0.0/msgpack-cxx-7.0.0.tar.gz | tar xz \
    && cp -r msgpack-cxx-7.0.0/include/* $CONSOLE_DEPS/include/ && rm -rf msgpack-cxx-7.0.0 \
    && curl -sSL https://archives.boost.io/release/1.91.0/source/boost_1_91_0.tar.gz | tar xz boost_1_91_0/boost boost_1_91_0/libs/url/src \
    && mv boost_1_91_0/boost $CONSOLE_DEPS/include/ && mkdir -p $CONSOLE_DEPS/src && mv boost_1_91_0/libs/url/src $CONSOLE_DEPS/src/boost_url \
    && rm -rf boost_1_91_0

# The CA bundle the app verifies servers against (Mozilla's, via curl).
RUN mkdir -p $CONSOLE_DEPS/share && curl -sSL -o $CONSOLE_DEPS/share/cacert.pem https://curl.se/ca/cacert.pem

# The UI font (DejaVu: free to redistribute).
RUN curl -sSL https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.tar.bz2 | tar xj \
    && cp dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf dejavu-fonts-ttf-2.37/ttf/DejaVuSans-Bold.ttf $CONSOLE_DEPS/share/ \
    && rm -rf dejavu-fonts-ttf-2.37

WORKDIR /
