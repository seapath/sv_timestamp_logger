FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    bison \
    ca-certificates \
    clang \
    cmake \
    flex \
    ninja-build \
    wget \
    make \
    && rm -rf /var/lib/apt/lists/*

RUN set -x \
  && wget -qO- https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz | tar xzf - \
  && mkdir libpcap-1.10.4/build \
  && cd libpcap-1.10.4/build \
  && ../configure \
    --prefix=/usr \
    --disable-shared \
    --disable-usb \
    --disable-bluetooth \
    --disable-dbus \
    --disable-rdma \
    --disable-ipv6 \
    --disable-optimizer-dbg \
    --disable-yydebug \
  && make -j \
  && make install \
  && cd ../../ && rm -rf libpcap-1.10.4

WORKDIR /build
COPY CMakeLists.txt /build
COPY lib/ /build/lib
COPY sv_timestamp_logger.* /build/

RUN ls /build && \
  mkdir build && cd build && \
  cmake -G Ninja .. && \
  ninja sv_timestamp_logger

FROM ubuntu:22.04

COPY --from=builder /build/build/sv_timestamp_logger /usr/bin/sv_timestamp_logger

ENTRYPOINT ["/usr/bin/sv_timestamp_logger"]
