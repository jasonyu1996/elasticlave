#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

source source.sh
mkdir -p build && cd build
cmake .. -Dfiresim=y
make $*


