# Thu Apr 27 2023
ARG BCC_COMMIT 4e09e97ef9bc4716d0e2578338b1e441a0193fd7

FROM ubuntu:20.04 as base

RUN apt-get -y update # 77

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install tzdata


FROM base as build

RUN apt-get -y install zip bison build-essential cmake flex git libedit-dev \
    libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
    liblzma-dev arping netperf iperf
RUN apt-get -y install clang-12 pkg-config
RUN ln -sf /usr/bin/clang-12 /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-12 /usr/bin/llvm-strip

RUN cd / && \
    git clone https://github.com/iovisor/bcc && \
    cd /bcc && \
    git reset --hard $BCC_COMMIT && \
    git submodule update --init --recursive
# Pre-compile objects
RUN cd /bcc/libbpf-tools && \
    make bashreadline

ADD linkevents.c linkevents.h linkevents.bpf.c /bcc/libbpf-tools/
RUN cd /bcc/libbpf-tools && \
    make APP_ALIASES= APPS=linkevents linkevents && \
    install linkevents /usr/bin/


FROM base as runtime

RUN apt-get -y install zlib1g libelf1

COPY --from=build /usr/bin/linkevents /usr/bin/
