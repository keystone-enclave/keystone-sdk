CC = riscv64-unknown-linux-gnu-gcc
LD = riscv64-unknown-linux-gnu-ld

SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib

SDK_INCLUDE_APP_DIR = $(SDK_LIB_DIR)/app/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
KEYEDGE_INCLUDE_DIR = $(KEYEDGE_DIR)/target/include
PROJECT_KEYEDGE_INClUDE_DIR = ../keyedge
FLATCC_INCLUDE_DIR = $(KEYEDGE_DIR)/flatcc/include

APP_LDS = app.lds

CFLAGS += -I$(SDK_INCLUDE_APP_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(FLATCC_INCLUDE_DIR) -I$(KEYEDGE_INCLUDE_DIR) -I$(PROJECT_KEYEDGE_INClUDE_DIR) -Wall -Werror
LDFLAGS = -static -L$(SDK_LIB_DIR) -L$(KEYEDGE_DIR)/lib

EAPP = eapp
OBJS = $(EAPP).o

all: $(EAPP)

$(EAPP): $(OBJS)
	$(LD) $(LDFLAGS) -T $(APP_LDS) \
	-o $(EAPP) \
	$(OBJS) \
	$(SDK_LIB_DIR)/libkeystone-eapp.a \
	$(SDK_LIB_DIR)/libkeystone-edge.a \
	$(KEYEDGE_DIR)/lib/flatccrt.a
	chmod -x $@


$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(APP_BIN) $(EXTRA_CLEAN)
