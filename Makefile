CC = clang
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

SRC_DIR = src/ebpf
OBJ_DIR = src/ebpf

all: $(OBJ_DIR)/main.bpf.o

$(OBJ_DIR)/main.bpf.o: $(SRC_DIR)/main.bpf.c $(SRC_DIR)/logscanxdp.h $(SRC_DIR)/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o
