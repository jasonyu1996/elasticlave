#!/bin/bash

set -e

################################################################
#                   Replace the variables                      #
################################################################
NAME=tests
VAULT_DIR=`dirname $0`
BUILD_COMMAND=make
#OUTPUT_DIR=$KEYSTONE_SDK_DIR/../buildroot_overlay/root/$NAME
OUTPUT_DIR=$KEYSTONE_SDK_DIR/../build/overlay/root/
EYRIE_DIR=$KEYSTONE_SDK_DIR/rts/eyrie
EYRIE_PLUGINS="freemem"
PACKAGE_FILES="
               test-runner.riscv \
			   $EYRIE_DIR/eyrie-rt \
               test \
               lock-futex/host/lock-futex.riscv \
               lock-futex/enclaves/lock-futex-a.eapp_riscv \
               lock-futex/enclaves/lock-futex-b.eapp_riscv \
               lock-spatial/host/lock-spatial.riscv \
               lock-spatial/enclaves/lock-spatial-s.eapp_riscv \
               lock-spatial/enclaves/lock-spatial-c.eapp_riscv \
               lock-native/lock-native.riscv \
               lock/host/lock.riscv \
               lock/enclaves/lock-a.eapp_riscv \
               lock/enclaves/lock-b.eapp_riscv \
               iozone/iozone.eapp_riscv \
               iozone/iozone-baseline.eapp_riscv \
               iozone/iozone.native \
               "

OTHER_FILES="
               icall-proxy-3-baseline/host/icall-proxy-3-baseline.riscv \
               icall-proxy-3-baseline/enclaves/icall-proxy-3-baseline-c.eapp_riscv \
               icall-proxy-3-baseline/enclaves/icall-proxy-3-baseline-s.eapp_riscv \
               icall-proxy-3-baseline/enclaves/icall-proxy-3-baseline-p.eapp_riscv \
               icall-proxy-3-ne/host/icall-proxy-3-ne.riscv \
               icall-proxy-3-ne/enclaves/icall-proxy-3-ne-c.eapp_riscv \
               icall-proxy-3-ne/enclaves/icall-proxy-3-ne-s.eapp_riscv \
               icall-proxy-3-ne/enclaves/icall-proxy-3-ne-p.eapp_riscv \
               icall-proxy-3/host/icall-proxy-3.riscv \
               icall-proxy-3/enclaves/icall-proxy-3-c.eapp_riscv \
               icall-proxy-3/enclaves/icall-proxy-3-s.eapp_riscv \
               icall-proxy-3/enclaves/icall-proxy-3-p.eapp_riscv \
               icall-server-baseline/host/icall-server-baseline.riscv \
               icall-server-baseline/enclaves/icall-server-baseline-c.eapp_riscv \
               icall-server-baseline/enclaves/icall-server-baseline-s.eapp_riscv \
               icall-server-ne/host/icall-server-ne.riscv \
               icall-server-ne/enclaves/icall-server-ne-c.eapp_riscv \
               icall-server-ne/enclaves/icall-server-ne-s.eapp_riscv \
               icall-server/host/icall-server.riscv \
               icall-server/enclaves/icall-server-c.eapp_riscv \
               icall-server/enclaves/icall-server-s.eapp_riscv \
               icall-consumer-baseline/host/icall-consumer-baseline.riscv \
               icall-consumer-baseline/enclaves/icall-consumer-baseline-c.eapp_riscv \
               icall-consumer-baseline/enclaves/icall-consumer-baseline-s.eapp_riscv \
               icall-consumer-ne/host/icall-consumer-ne.riscv \
               icall-consumer-ne/enclaves/icall-consumer-ne-c.eapp_riscv \
               icall-consumer-ne/enclaves/icall-consumer-ne-s.eapp_riscv \
               icall-consumer/host/icall-consumer.riscv \
               icall-consumer/enclaves/icall-consumer-c.eapp_riscv \
               icall-consumer/enclaves/icall-consumer-s.eapp_riscv \
               iozone/iozone.native \
               "
PACKAGE_SCRIPT="./test"

################################################################
#                       Sanity Check                           #
################################################################

# check if KEYSTONE_SDK_DIR is set
if [[ $KEYSTONE_SDK_DIR = "" ]]; then
  echo "KEYSTONE_SDK_DIR is not set"
  exit 1
fi

if [[ ! -d $KEYSTONE_SDK_DIR ]]; then
  echo "Invalid KEYSTONE_SDK_DIR '$KEYSTONE_SDK_DIR'"
  exit 1
fi

# check if riscv tools are in PATH
if ! (
  $(command -v riscv64-unknown-elf-g++ > /dev/null) &&
  $(command -v riscv64-unknown-linux-gnu-g++ > /dev/null) &&
  $(command -v riscv64-unknown-elf-gcc > /dev/null) &&
  $(command -v riscv64-unknown-linux-gnu-gcc > /dev/null)
  ); then
  echo "riscv tools are not in PATH"
  exit 1
fi

# check if OUTPUT_DIR is set
if [[ $OUTPUT_DIR = "" ]]; then
  echo "OUTPUT_DIR is not set"
  exit 1
fi

# check if EYRIE_DIR is valid
if [[ ! -d $EYRIE_DIR ]]; then
  echo "Invalid EYRIE_DIR '$EYRIE_DIR'"
  exit 1
fi

################################################################
#                       Build Enclave                          #
################################################################

# create a build directory
OUTPUT_FILES_DIR=$OUTPUT_DIR/files
mkdir -p $OUTPUT_FILES_DIR

# build eyrie runtime
$EYRIE_DIR/build.sh $EYRIE_PLUGINS

# build the app
pushd $VAULT_DIR
$BUILD_COMMAND
for output in $PACKAGE_FILES; do
  if [ -e $output ]; then
    cp $output $OUTPUT_FILES_DIR
  fi
done
popd

# create vault archive & remove output files
makeself --noprogress "$OUTPUT_FILES_DIR" "$OUTPUT_DIR/$NAME.ke" "Keystone vault archive" $PACKAGE_SCRIPT
rm -rf $OUTPUT_FILES_DIR
