CC = riscv64-unknown-linux-gnu-gcc
LINK = riscv64-unknown-linux-gnu-ld
LINKFLAGS = -static -pie --no-dynamic-linker -z text
INCLUDE_DIR = -I include -I ../edge/include -I $(LIBSODIUM_DIR)/include
AR = riscv64-unknown-elf-ar
ARFLAGS = rcs

OPTIONS_FLAGS ?=
CFLAGS = -fPIE -Wall $(OPTIONS_FLAGS) -fno-plt

ASM_SRCS = $(wildcard src/*.s) $(wildcard src/*.S)
C_SRCS = $(wildcard src/*.c)

A_OBJS = $(patsubst %.s,%.o,$(ASM_SRCS))
C_OBJS = $(patsubst %.c,%.o,$(C_SRCS))
ARCHIVE_C_OBJS=$(C_OBJS)
#ARCHIVE_C_OBJS = $(filter-out src/string.o,$(C_OBJS))

TARGET = ../libkeystone-eapp.a

all: $(TARGET)

$(A_OBJS): %.o : %.s
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c $< -o $@
$(C_OBJS): %.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_DIR) -c $< -o $@
$(TARGET): $(A_OBJS) $(C_OBJS)
	$(AR) $(ARFLAGS) $@ $(A_OBJS) $(ARCHIVE_C_OBJS) 


clean:
	rm -f $(A_OBJS) $(C_OBJS) $(TARGET)
