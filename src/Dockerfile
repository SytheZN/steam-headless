FROM registry.fedoraproject.org/fedora:43 AS builder

RUN dnf install -y \
    git \
    meson \
    ninja-build \
    gcc \
    gcc-c++ \
    glibc-devel.i686 \
    cmake \
    pipewire-devel \
    hwdata \
    libX11-devel \
    wayland-devel \
    wayland-protocols-devel \
    vulkan-loader-devel \
    libXdamage-devel \
    libXcomposite-devel \
    libXcursor-devel \
    libXxf86vm-devel \
    libXtst-devel \
    libXres-devel \
    libXmu-devel \
    libxkbcommon-devel \
    pixman-devel \
    libudev-devel \
    libdrm-devel \
    libseat-devel \
    libinput-devel \
    xorg-x11-server-Xwayland-devel \
    xcb-util-wm-devel \
    libdecor-devel \
    glslang \
    luajit-devel \
    SDL2-devel \
    libei-devel \
    libeis-devel \
    && dnf clean all

RUN git clone https://github.com/ValveSoftware/gamescope.git /gamescope

WORKDIR /gamescope

RUN git submodule update --init --recursive

COPY gamescope-patches/ /tmp/gamescope-patches/
RUN for patch in /tmp/gamescope-patches/*.patch; do git apply "$patch"; done

# TEMPORARY INSTALLS FOR BUILD
#RUN dnf install -y  && dnf clean all

RUN meson build/ --prefix=/usr --buildtype=release \
    -Dinput_emulation=enabled \
    -Dpipewire=enabled \
    -Drt_cap=enabled \
    -Ddrm_backend=enabled \
    -Dsdl2_backend=enabled
RUN ninja -C build/

# Build uinput-proxy
COPY uinput-proxy/ /uinput-proxy/
WORKDIR /uinput-proxy
RUN make dist

FROM registry.fedoraproject.org/fedora:43 AS runtime

RUN dnf install -y \
    https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm \
    https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm \
    && dnf clean all

RUN dnf install -y \
    steam \
    gamescope \
    pipewire-pulse \
    util-linux \
    dbus-daemon \
    libei \
    libeis \
    pipewire-utils \
    konsole \
    labwc \
    procps-ng \
    xdotool \
    xprop \
    swaybg \
    waybar \
    wlr-randr \
    `# Weak dependencies` \
    lsof \
    && dnf clean all

# TEMPORARY INSTALLS FOR RUNTIME
RUN dnf install -y jstest-gtk xwininfo && dnf clean all

# Overwrite distro gamescope binary with our custom build
COPY --from=builder /gamescope/build/src/gamescope /usr/bin/gamescope

# Install uinput-proxy
COPY --from=builder /uinput-proxy/uinput-daemon /usr/local/bin/
RUN chmod 4755 /usr/local/bin/uinput-daemon
COPY --from=builder /uinput-proxy/uinput-install /usr/local/bin/
RUN chmod 4755 /usr/local/bin/uinput-install
COPY --from=builder /uinput-proxy/dist/uinput/ /opt/uinput/

RUN touch /.container

RUN useradd -m -u 1000 steam && \
    groupadd -f input && \
    usermod -aG input steam && \
    mkdir -p /home/steam/.local/share/Steam && \
    mkdir -p /home/steam/.local/state/wireplumber && \
    mkdir -p /tmp/runtime && \
    chown -R steam:steam /home/steam /tmp/runtime && \
    chmod 700 /tmp/runtime

COPY root/ /
COPY post-copy.sh /tmp/
RUN /bin/bash /tmp/post-copy.sh

USER steam
WORKDIR /home/steam

ENV GAMESCOPE_BACKEND=
ENV DEFAULT_SESSION=
ENV HEADLESS_DEBUG=

CMD ["/start.sh"]
