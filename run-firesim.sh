#!/bin/bash

set -e

if [ -z "$FIRESIM_HOME" ]; then
    FIRESIM_HOME=firesim
fi

#ln -srnf build/riscv-pk.build/bbl "$FIRESIM_HOME"/deploy/workloads/elasticlave/bbl
#ln -srnf build/buildroot.build/images/rootfs.ext2 "$FIRESIM_HOME"/deploy/workloads/elasticlave/rootfs.ext2

cd "$FIRESIM_HOME"
source sourceme-f1-manager.sh
cd -

firesim launchrunfarm && firesim infrasetup
firesim runworkload > /dev/null 2>&1 &

sleep 20

LOG_FILE="$FIRESIM_HOME"/deploy/logs/"$(ls -1t "$FIRESIM_HOME"/deploy/logs | head -n1)"

IP=$(awk '/Instance IP/ { print $9; exit 0; }' "$LOG_FILE")

ssh -t $IP screen -r fsim0


yes yes | firesim terminaterunfarm

