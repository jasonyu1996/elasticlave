#!/bin/bash

firesim launchrunfarm && firesim infrasetup
firesim runworkload > /dev/null 2>&1 &

sleep 5

LOG_FILE=firesim/deploy/logs/"$(ls -1t firesim/deploy/logs | head -n1)"

IP=$(awk '/Instance IP/ { print $9; exit 0; }' "$LOG_FILE")

ssh $IP screen -r fsim0


yes yes | firesim terminaterunfarm

