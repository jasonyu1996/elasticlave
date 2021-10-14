#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

source source.sh
cd musl
CFLAGS=-fPIC ./configure --prefix=/keystone/musl/musl-build --target=riscv64-unknown-linux-gnu
make $1
make install

