FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Singapore


ENV ELASTICLAVE_TOOLS=/tools
ENV RISCV=${ELASTICLAVE_TOOLS}/riscv
ENV PATH=${RISCV}/bin:${PATH}
WORKDIR ${ELASTICLAVE_TOOLS}

RUN apt-get update && apt-get install -y autoconf automake autotools-dev bc \
    bison build-essential curl expat libexpat1-dev flex gawk gcc git \
    gperf libgmp-dev libmpc-dev libmpfr-dev libtool texinfo tmux \
    patchutils zlib1g-dev wget bzip2 patch vim-common lbzip2 python \
    pkg-config libglib2.0-dev libpixman-1-dev libssl-dev screen \
    device-tree-compiler expect makeself unzip cpio rsync cmake \
    ninja-build

ADD setup ${ELASTICLAVE_TOOLS}/
ADD .prebuilt_tools_shasums ${ELASTICLAVE_TOOLS}/
RUN ./setup

RUN apt-get install -y libpng-dev

