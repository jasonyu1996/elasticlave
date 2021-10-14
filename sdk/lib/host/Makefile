CC = riscv64-unknown-linux-gnu-g++
INCLUDE_DIR = -I include/ -I ../edge/include
SRC_DIR = src

OPTIONS_FLAGS+=-DLINUX_SYSCALL_WRAPPING -DIO_SYSCALL_WRAPPING -DFAST_IO_SYSCALL_WRAPPING

CCFLAGS = -Wall $(INCLUDE_DIR) $(OPTIONS_FLAGS)
#SRCS = keystone.cpp elffile.cpp elf.cpp elf32.cpp elf64.cpp sha3.cpp memory.cpp incoming_syscall.cpp edge_dispatch.cpp
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst %.cpp,%.o,$(SRCS))
AR = riscv64-unknown-linux-gnu-ar
ARFLAGS = rcs

TARGET=../libkeystone-host.a

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OBJS): %.o: %.cpp
	$(CC) $(CCFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(TARGET)
