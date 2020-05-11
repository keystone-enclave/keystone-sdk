CC = riscv64-unknown-linux-gnu-g++
LD = riscv64-unknown-linux-gnu-ld

SDK_LIB_DIR = $(KEYSTONE_SDK_DIR)/lib

SDK_INCLUDE_HOST_DIR = $(SDK_LIB_DIR)/host/include
SDK_INCLUDE_EDGE_DIR = $(SDK_LIB_DIR)/edge/include
KEYEDGE_INCLUDE_DIR = $(KEYEDGE_DIR)/target/include
PROJECT_KEYEDGE_INClUDE_DIR = ../keyedge
FLATCC_INCLUDE_DIR = $(KEYEDGE_DIR)/flatcc/include

CCFLAGS = -g -I$(SDK_INCLUDE_HOST_DIR) -I$(SDK_INCLUDE_EDGE_DIR) -I$(FLATCC_INCLUDE_DIR) -I$(KEYEDGE_INCLUDE_DIR) -I$(PROJECT_KEYEDGE_INClUDE_DIR) -std=c++11 -Wall -Werror
LDFLAGS = -L$(SDK_LIB_DIR) -L$(KEYEDGE_DIR)/lib

HOST = host
OBJS = $(HOST).o

all: $(HOST)

$(HOST): $(OBJS)
	$(CC) $(LDFLAGS) $(CCFLAGS) \
	-o $(HOST) \
	$(OBJS) \
	$(SDK_LIB_DIR)/libkeystone-host.a \
	$(SDK_LIB_DIR)/libkeystone-edge.a \
	$(KEYEDGE_DIR)/lib/flatccrt.a
	
$(OBJS): %.o: %.cpp
	$(CC) $(CCFLAGS) -c $<
	
clean:
	rm -f *.o $(HOST)
