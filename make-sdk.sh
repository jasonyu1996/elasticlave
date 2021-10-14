#!/bin/bash

CURDIR=$(dirname $(readlink -f $0))

cd $CURDIR

source source.sh
make -C sdk/lib $*
make -C sdk/rts/eyrie $*


