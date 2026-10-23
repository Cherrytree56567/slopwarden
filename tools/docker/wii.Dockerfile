# Wii build environment: devkitPPC + libogc + SDL2, plus the core's dependencies built for
# the Wii (32-bit big-endian PowerPC, newlib, no OS):
#   docker build -t clientwarden-wii -f tools/docker/wii.Dockerfile tools/docker
FROM devkitpro/devkitppc:latest

RUN apt-get update && apt-get install -y --no-install-recommends python3 xz-utils curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV WII_DEPS=/opt/wii-deps
ARG MACHDEP="-DGEKKO -mrvl -mcpu=750 -meabi -mhard-float"
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
    && cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=$DEVKITPRO/cmake/Wii.cmake -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=$WII_DEPS \
    && cmake --build build -j8 && cmake --install build && cd .. && rm -rf mbedtls-3.6.5

# Botan with just what the core uses (and ChaCha_RNG for the Wii's own generator).
RUN curl -sSL https://botan.randombit.net/releases/Botan-3.11.1.tar.xz | tar xJ \
    && cd Botan-3.11.1 \
    && python3 configure.py --os=none --cpu=ppc32 --cc=gcc --cc-bin=$DEVKITPPC/bin/powerpc-eabi-g++ \
        --ar-command=$DEVKITPPC/bin/powerpc-eabi-ar --cxxflags="$MACHDEP -O2" \
        --build-targets=static --without-documentation --prefix=$WII_DEPS --minimized-build \
        --enable-modules=aes,cbc,hmac,sha1,sha2_32,sha2_64,hkdf,pbkdf2,argon2,rsa,eme_oaep,eme_pkcs1,emsa_pkcs1,x509,pubkey,base32,base64,hex,hotp,chacha_rng,hmac_drbg,pbes2,pem \
    && make -j8 && make install && cd .. && rm -rf Botan-3.11.1

# Header-only: nlohmann/json, spdlog (bundled fmt), msgpack-cxx; Boost headers (Boost.URL's
# sources are compiled into the app).
RUN mkdir -p $WII_DEPS/include/nlohmann \
    && curl -sSL -o $WII_DEPS/include/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp \
    && curl -sSL https://github.com/gabime/spdlog/archive/refs/tags/v1.17.0.tar.gz | tar xz \
    && cp -r spdlog-1.17.0/include/spdlog $WII_DEPS/include/ && rm -rf spdlog-1.17.0 \
    && curl -sSL https://github.com/msgpack/msgpack-c/releases/download/cpp-7.0.0/msgpack-cxx-7.0.0.tar.gz | tar xz \
    && cp -r msgpack-cxx-7.0.0/include/* $WII_DEPS/include/ && rm -rf msgpack-cxx-7.0.0 \
    && curl -sSL https://archives.boost.io/release/1.91.0/source/boost_1_91_0.tar.gz | tar xz boost_1_91_0/boost boost_1_91_0/libs/url/src \
    && mv boost_1_91_0/boost $WII_DEPS/include/ && mkdir -p $WII_DEPS/src && mv boost_1_91_0/libs/url/src $WII_DEPS/src/boost_url \
    && rm -rf boost_1_91_0

# The CA bundle the app verifies servers against (Mozilla's, via curl).
RUN mkdir -p $WII_DEPS/share && curl -sSL -o $WII_DEPS/share/cacert.pem https://curl.se/ca/cacert.pem

# The UI font (DejaVu: free to redistribute).
RUN curl -sSL https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.tar.bz2 | tar xj \
    && cp dejavu-fonts-ttf-2.37/ttf/DejaVuSans.ttf dejavu-fonts-ttf-2.37/ttf/DejaVuSans-Bold.ttf $WII_DEPS/share/ \
    && rm -rf dejavu-fonts-ttf-2.37

WORKDIR /
