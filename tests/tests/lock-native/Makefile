TARGET_APP=lock-native.riscv
SRC_C=lock-native.c

$(TARGET_APP): $(SRC_C)
	$(CC) $(CFLAGS_HOST) $^ $(LIBC) $(LIBPTHREAD) -o $@

.PHONY: clean

clean:
	rm -rf $(TARGET_APP)

