APP = icall-proxy-3-ne-c icall-proxy-3-ne-s icall-proxy-3-ne-p
APP_C_SRCS=

APP_O_OBJS = $(patsubst %,%.o, $(APP))
APP_C_OBJS = $(patsubst %.c,%.o, $(APP_C_SRCS))
APP_A_OBJS = $(patsubst %.s,%.o, $(APP_A_SRCS))
APP_OBJS = $(APP_O_OBJS) $(APP_C_OBJS)
APP_LDS ?= ../../app.lds

APP_BIN = $(patsubst %,%.eapp_riscv,$(APP))

all: $(APP_BIN)

$(APP_OBJS): %.o: %.c
	$(CC) $(CFLAGS_EAPP) -c $<

$(APP_BIN): %.eapp_riscv : %.o $(APP_C_OBJS) $(LIB_EAPP)
	$(CC) $(LDFLAGS_EAPP) -o $@ $^ $(LIBSODIUM_DIR)/.libs/libsodium.a
   
clean:
	rm -f *.o $(APP_BIN) $(EXTRA_CLEAN)

