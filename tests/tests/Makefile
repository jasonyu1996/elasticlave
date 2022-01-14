
export CC:=riscv64-unknown-linux-gnu-gcc
export CXX:=riscv64-unknown-linux-gnu-g++
export LD:=riscv64-unknown-linux-gnu-ld
export AR:=riscv64-unknown-linux-gnu-ar

export CC_HOST:=riscv64-unknown-linux-gnu-gcc
export CXX_HOST:=riscv64-unknown-linux-gnu-g++
export LD_HOST:=riscv64-unknown-linux-gnu-ld
export AR_HOST:=riscv64-unknown-linux-gnu-ar


export LIBC:=$(MUSL_DIR)/lib/libc.a
export LIBPTHREAD:=$(MUSL_DIR)/lib/libpthread.a
export RCRT:=$(MUSL_DIR)/lib/rcrt1.o
export LIBCC:=-lgcc -lgcc_eh


export OUT=$(CURDIR)/build
export COPY=cp
export MKDIR=mkdir

export SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib
SDK_APP_LIB = $(SDK_LIB_DIR)/libkeystone-eapp.a
SDK_EDGE_LIB = $(SDK_LIB_DIR)/libkeystone-edge.a
SDK_HOST_LIB = $(SDK_LIB_DIR)/libkeystone-host.a
SDK_VERIFIER_LIB = $(SDK_LIB_DIR)/libkeystone-verifier.a
SDK_INCLUDE_APP_DIR = $(SDK_LIB_DIR)/app/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
SDK_INCLUDE_HOST_DIR = $(SDK_LIB_DIR)/host/include
SDK_INCLUDE_VERIFIER_DIR = $(SDK_LIB_DIR)/verifier

export CFLAGS_EAPP:=-Wall -I. \
	-I$(SDK_INCLUDE_APP_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(MUSL_DIR)/include/
export CFLAGS_HOST:=-I. \
	-I$(SDK_INCLUDE_HOST_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(SDK_INCLUDE_VERIFIER_DIR) -std=c++11
export LDFLAGS_EAPP:=-static
export LDFLAGS_HOST:= -L$(SDK_LIB_DIR)

export LDS_EAPP := $(CURDIR)/app.lds

export ARFLAGS := rcs


export LIB_EAPP:=$(SDK_APP_LIB) $(SDK_EDGE_LIB)
export LIB_HOST:=$(SDK_HOST_LIB) $(SDK_EDGE_LIB)

export OBJCOPY:= riscv64-unknown-linux-gnu-objcopy

export RUNTIME_FILE:=$(KEYSTONE_SDK_DIR)/rts/eyrie/eyrie-rt

SDK_LIB_DIR =$(KEYSTONE_SDK_DIR)/lib
SDK_HOST_LIB = $(SDK_LIB_DIR)/libkeystone-host.a
SDK_EDGE_LIB = $(SDK_LIB_DIR)/libkeystone-edge.a

SDK_INCLUDE_HOST_DIR = $(SDK_LIB_DIR)/host/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include

RUNTIME=eyrie-rt
RUNNER=test-runner.riscv
CCFLAGS = -I$(SDK_INCLUDE_HOST_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(SDK_INCLUDE_VERIFIER_DIR) -std=c++11 
LDFLAGS = -L$(SDK_LIB_DIR)

SRCS = $(patsubst %.riscv, %.cpp, $(RUNNER))
OBJS = $(patsubst %.riscv, %.o,$(RUNNER)) $(KEYSTONE_OBJ) edge_wrapper.o

include mkconfig.mk


all:  $(OBJS) $(SDK_HOST_LIB) $(SDK_EDGE_LIB) $(SDK_VERIFIER_LIB)
	$(CXX_HOST) $(CFLAGS_HOST) $(LDFLAGS_HOST) -o $(RUNNER) $^
	$(foreach test, $(TESTS),\
		$(MAKE) -C $(test);\
	)
	$(foreach test, $(NATIVE_TESTS),\
		$(MAKE) -C $(test);\
	)
	$(foreach test, $(BASELINE_TESTS),\
		$(MAKE) -C $(test);\
	)
	$(foreach test, $(EXTRA_TESTS),\
		$(MAKE) -C $(test);\
	)
	rm -f test
	$(foreach test, $(TESTS), \
		echo "echo 'testing $(test)'" >> test;\
		echo "./$(RUNNER) $(test).eapp_riscv $(RUNTIME)" >> test; \
	)
	$(foreach test, $(NATIVE_TESTS), \
		echo "echo 'testing native $(test)'" >> test;\
		echo "./$(test).native" >> test; \
	)
	$(foreach test, $(BASELINE_TESTS), \
		echo "echo 'testing baseline $(test)'" >> test;\
		echo "./$(RUNNER) $(test)-baseline.eapp_riscv $(RUNTIME)" >> test; \
	)
	$(foreach test, $(EXTRA_TESTS), \
		echo "echo 'testing $(test)'" >> test;\
		echo './$(test).riscv $$@' >> test; \
	)
	chmod +x test
	$(foreach pack, $(EXTRA_PACKS), \
		echo "Making $(pack)"; \
		$(MAKE) -C $(pack); \
		mkdir -p $(OUTPUT_DIR)/$(pack); \
		cp -r $(pack)/build/* $(OUTPUT_DIR)/$(pack);\
	)

$(OBJS): %.o: %.cpp
	$(CXX_HOST) $(CFLAGS_HOST) -c $^

clean:
	rm -f *.o *.riscv test
	$(foreach test, $(TESTS) $(NATIVE_TESTS) $(EXTRA_TESTS) $(EXTRA_PACKS), \
		$(MAKE) -C $(test) clean; \
	)
		
