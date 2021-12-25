#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

source source.sh
cd musl
CFLAGS=-fPIC ./configure --prefix=${CURDIR}/musl/musl-build --target=riscv64-unknown-linux-gnu
make
make install

