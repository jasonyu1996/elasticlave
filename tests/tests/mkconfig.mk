OUTPUT_DIR=$(KEYSTONE_SDK_DIR)/../build/overlay/root/
TESTS=iozone
EXTRA_TESTS=#lock lock-futex lock-spatial lock-native 
EXTRA_PACKS=#icall-server icall-server-ne icall-server-baseline icall-consumer icall-consumer-ne icall-consumer-baseline icall-proxy-3 icall-proxy-3-ne icall-proxy-3-baseline
BASELINE_TESTS=#iozone
NATIVE_TESTS=#iozone

