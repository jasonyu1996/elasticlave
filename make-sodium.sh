#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

#source source.sh
echo $PATH
cd libsodium
./autogen.sh
./configure --host=riscv64-unknown-linux-gnu --disable-ssp --disable-asm --without-pthreads
make

