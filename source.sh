export STATIC_TOOLCHAIN=$(pwd)/riscv/bin/
export STATIC_LIBC=$(pwd)/riscv-gnu-toolchain/glibc-pie/
export RISCV=$(pwd)/riscv/
export PATH=$RISCV/bin:$PATH
export KEYSTONE_SDK_DIR=$(pwd)/sdk
export LIBSODIUM_DIR=$(pwd)/libsodium/src/libsodium/
export MUSL_DIR=$(pwd)/musl/musl-build
