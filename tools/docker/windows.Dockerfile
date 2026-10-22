# Windows cross-build environment (MinGW-w64 + Rust windows-gnu + Wine for smoke tests):
#   docker build -t clientwarden-windows -f tools/docker/windows.Dockerfile tools/docker
# then see tools/docker/build-windows.sh.
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git curl ca-certificates pkg-config perl python3 python3-venv \
        g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix binutils-mingw-w64-x86-64 \
        wine64 wine xvfb xdotool imagemagick \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/conan && /opt/conan/bin/pip install --no-cache-dir conan==2.29.1
ENV PATH=/opt/conan/bin:/root/.cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --target x86_64-pc-windows-gnu
RUN conan profile detect
COPY cargo-config.toml /root/.cargo/config.toml
