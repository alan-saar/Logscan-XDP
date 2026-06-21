CC = clang
# CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -DDISABLE_OVERRIDE
# CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -DDISABLE_OVERRIDE -I/usr/include -I/usr/include/x86_64-linux-gnu
CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu

SRC_DIR = src/ebpf
OBJ_DIR = src/ebpf

all: $(OBJ_DIR)/main.bpf.o $(OBJ_DIR)/log_filter.bpf.o

$(OBJ_DIR)/main.bpf.o: $(SRC_DIR)/main.bpf.c $(SRC_DIR)/logscanxdp.h $(SRC_DIR)/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/log_filter.bpf.o: $(SRC_DIR)/log_filter.bpf.c $(SRC_DIR)/vmlinux.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o

.PHONY: integration-test
integration-test:
	@bash tests/integration/run_integration_test.sh
