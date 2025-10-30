# Makefile for BubbleSketch eBPF

# Kernel architecture
ARCH := $(shell uname -m)

# Compiler flags
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(ARCH)-linux-gnu -g -O2

#default values 
SKETCH ?= obubble
IFACE ?= veth-recv

# Files
BPF_SRC := $(basename $(SKETCH))_sketch_ebpf.c
BPF_OBJ := $(basename $(SKETCH))_sketch_ebpf.o
BPF_SKEL := $(basename $(SKETCH))_sketch_ebpf.skel.h
LOADER := $(basename $(SKETCH))_sketch_loader
LOADER_SRC := $(basename $(SKETCH))_sketch_loader.c

# Default target
all: $(BPF_OBJ) $(BPF_SKEL) $(LOADER)

# Compile eBPF object
$(BPF_OBJ): $(BPF_SRC)
	@echo "Compiling eBPF program: $<"
	clang $(BPF_CFLAGS) -c $< -o $@ || { echo "Error: failed to compile $<"; exit 1; }

# Generate skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	@echo "Generating skeleton header: $@"
	@sudo bpftool gen skeleton $(BPF_OBJ) > $@ || { echo "Error: failed to generate skeleton $@"; exit 1; }

# Compile loader
$(LOADER): $(LOADER_SRC)
	@echo "Compiling loader: $<"
	clang -O2 -g -o $@ $< -lbpf -lelf || { echo "Error: failed to compile loader"; exit 1; }

# Run loader
run: $(LOADER)
	@echo "Running loader..."
	@sudo ./$(LOADER)  $(IFACE) > ../sketch_output.txt || { echo "Error: loader execution failed"; exit 1; }

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -f $(BPF_OBJ) $(BPF_SKEL) $(LOADER)

