#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

git submodule sync --recursive
git submodule update --init --recursive

mkdir riscv
export RISCV=$(pwd)/riscv
export PATH=$PATH:$RISCV/bin
cd riscv-gnu-toolchain
./configure --prefix=$RISCV
make && make linux
cd ..

./make-sodium.sh

# build tests in SDK
make -C sdk
export KEYSTONE_SDK_DIR=$(pwd)/sdk
