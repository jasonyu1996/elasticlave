CC = riscv64-unknown-linux-gnu-gcc
CXX = riscv64-unknown-linux-gnu-g++
INCLUDE_DIR = -I include/ -I ../host/include -I ../app/include -I $(LIBSODIUM_DIR)/include
SRC_DIR = src

OPTIONS_FLAGS+=-DIO_SYSCALL_WRAPPING -DFAST_IO_SYSCALL_WRAPPING

CCFLAGS = -fPIE -Wall $(INCLUDE_DIR) $(OPTIONS_FLAGS) -fno-plt
CXXFLAGS = -fPIE -Wall $(INCLUDE_DIR) $(OPTIONS_FLAGS) -fno-plt

SRCS = $(wildcard src/*.c)
CXX_SRCS =
OBJS = $(patsubst %.c,%.o,$(SRCS))
CXX_OBJS = $(patsubst %.cpp,%.o,$(CXX_SRCS))

AR = riscv64-unknown-elf-ar
ARFLAGS = rcs

TARGET=../libkeystone-edge.a

all: $(TARGET)

$(TARGET): $(OBJS) $(CXX_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OBJS): %.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

$(CXX_OBJS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(CXX_OBJS) $(TARGET)
