APP=iozone.eapp_riscv
APP_BASELINE=iozone-baseline.eapp_riscv
NATIVE_APP=iozone.native

CC	= cc
C89	= c89
GCC	= gcc
CCS	= /usr/ccs/bin/cc
NACC	= /opt/ansic/bin/cc
CFLAGS	=

SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib
SDK_APP_LIB = $(SDK_LIB_DIR)/libkeystone-eapp.a
SDK_EDGE_LIB = $(SDK_LIB_DIR)/libkeystone-edge.a
SDK_INCLUDE_APP_DIR = $(SDK_LIB_DIR)/app/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
CLIB = $(KEYSTONE_SDK_DIR)/../riscv-gnu-toolchain/glibc-pie/libc.a

MUSLIB=$(MUSL_DIR)/lib/libc.a
CRT=$(MUSL_DIR)/lib/rcrt1.o
GCCLIB=-lgcc -lgcc_eh

APP_LDS ?= ./app.lds


CFLAGS_EXTRA ?= 

CKEYSTONEX = riscv64-unknown-linux-gnu-gcc
LDKEYSTONEX = riscv64-unknown-linux-gnu-ld
CFLAGS_KEYSTONEX = -g -fpic -Wall -I$(SDK_INCLUDE_APP_DIR) -I$(SDK_INCLUDE_EDGE_DIR) $(CFLAGS_EXTRA)

#CFLAGS_KEYSTONEX = -g -fpic -Wall 
#LDFLAGS_KEYSTONEX = -static-pie -fpie -L$(SDK_LIB_DIR) -T $(APP_LDS)  -Wl,--no-dynamic-linker
LDFLAGS_KEYSTONEX = -g -nostartfiles -nostdlib -shared -Wl,-Bstatic -Wl,-Bsymbolic#-nostartfiles -nostdlib -static-pie -Wl,-z,text #-shared -Bstatic -Bsymbolic


# If your Linux kernel supports preadv and pwritev system calls 
# and you want iozone to use them, add -DHAVE_PREADV -DHAVE_PWRITEV
# to CFLAGS

all: $(APP) $(APP_BASELINE) $(NATIVE_APP)
clean:
	rm -f *.o *.no $(APP) $(NATIVE_APP) fileop pit_server

rpm:
	cp ../../iozone*.tar /usr/src/red*/SO*
	rpmbuild -ba spec.in


#
# Turn on the optimizer, largefiles, Posix async I/O and threads.
#
#
# GNU 'C' compiler KeystoneX  build with no threads, largefiles, no async I/O 
#
$(APP):	iozone_keystonex.o libbif.o $(MUSLIB) $(SDK_APP_LIB) $(SDK_EDGE_LIB)
	$(CKEYSTONEX) $(LDFLAGS_KEYSTONEX) $(CRT) iozone_keystonex.o libbif.o $(MUSLIB) $(GCCLIB) $(SDK_APP_LIB) $(SDK_EDGE_LIB) -T $(APP_LDS) -o $(APP)

$(APP_BASELINE):	iozone_keystonex_baseline.o libbif.o $(MUSLIB) $(SDK_APP_LIB) $(SDK_EDGE_LIB)
	$(CKEYSTONEX) $(LDFLAGS_KEYSTONEX) $(CRT) iozone_keystonex_baseline.o libbif.o $(MUSLIB) $(GCCLIB) $(SDK_APP_LIB) $(SDK_EDGE_LIB) -T $(APP_LDS) -o $(APP_BASELINE)

$(NATIVE_APP): iozone.no libbif.no
	$(CC_HOST) $(CFLAGS_HOST) $(LDFLAGS_HOST) -o $@ $^




# --startiozone_keystonex.o libbif.o $(MUSLIB) $(SDK_APP_LIB) $(SDK_EDGE_LIB)-group $(CLIB) $(GCCLIB) --end-group $(SDK_APP_LIB) $(SDK_EDGE_LIB) -o $(APP)

iozone_keystonex.o:	iozone.c libbif.c
	@echo ""
	@echo "Building iozone for KeystoneX"
	@echo ""
	$(CKEYSTONEX) -Wmissing-prototypes -Wall -c -Dunix -DHAVE_ANSIC_C \
		-Dlinux -DNO_THREADS $(CFLAGS_KEYSTONEX) -DHYBRID_IO iozone.c \
		-DNAME='"linux"' -o iozone_keystonex.o
	$(CKEYSTONEX) -c -Dlinux -DHAVE_ANSIC_C -DNO_THREADS \
		$(CFLAGS_KEYSTONEX) -DHYBRID_IO libbif.c -o libbif.o

iozone_keystonex_baseline.o:	iozone.c libbif.c
	@echo ""
	@echo "Building iozone for KeystoneX"
	@echo ""
	$(CKEYSTONEX) -Wmissing-prototypes -Wall -c -Dunix -DHAVE_ANSIC_C \
		-Dlinux -DNO_THREADS $(CFLAGS_KEYSTONEX) iozone.c \
		-DNAME='"linux"' -o iozone_keystonex_baseline.o
	$(CKEYSTONEX) -c -Dlinux -DHAVE_ANSIC_C -DNO_THREADS \
		$(CFLAGS_KEYSTONEX) libbif.c -o libbif.o


iozone.no:	iozone.c libbif.c
	@echo ""
	@echo "Building iozone for KeystoneX"
	@echo ""
	$(CC_HOST) -Wmissing-prototypes -Wall -c -Dunix -DHAVE_ANSIC_C \
		-Dlinux -DNO_THREADS $(CFLAGS_HOST) iozone.c \
		-DNAME='"linux"' -o iozone.no
	$(CC_HOST) -c -Dlinux -DHAVE_ANSIC_C -DNO_THREADS \
		$(CFLAGS_HOST) libbif.c -o libbif.no


.PHONY: all

