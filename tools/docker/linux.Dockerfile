# Linux build environment: docker build -t clientwarden-linux -f tools/docker/linux.Dockerfile .
# then see tools/docker/build-linux.sh.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential g++-14 gcc-14 cmake ninja-build git curl ca-certificates pkg-config \
        python3 python3-pip python3-venv perl \
        libsecret-1-dev libglib2.0-dev \
        libxkbcommon-dev libxkbcommon-x11-0 libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev \
        libx11-xcb-dev libxcb1-dev libfontconfig1-dev libfreetype-dev libgtk-3-dev \
        libvulkan1 mesa-vulkan-drivers \
        xvfb xdotool imagemagick dbus-x11 gnome-keyring \
    && rm -rf /var/lib/apt/lists/*
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 140 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 140

RUN python3 -m venv /opt/conan && /opt/conan/bin/pip install --no-cache-dir conan==2.29.1
ENV PATH=/opt/conan/bin:/root/.cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
RUN conan profile detect && sed -i 's/compiler.cppstd=.*/compiler.cppstd=20/' /root/.conan2/profiles/default
