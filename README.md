# In-Kernel Heavy Hitter Detection using eBPF-based Bubble Sketch Variants

This repository implements various eBPF-based Bubble Sketch variants for detecting heavy hitters in network traffic directly in the kernel.

## Prerequisites

- Linux kernel with eBPF support
- Clang compiler
- libbpf development libraries
- libpcap (for user-space variant)
- tcpreplay (for testing)
- Python 3 (for accuracy calculations)

## Initial Setup

Before running any sketch algorithms, set up the virtual Ethernet pair for eBPF testing:

```bash
chmod +x setup_veth.sh
./setup_veth.sh
```

## Repository Structure

The repository contains the following eBPF Bubble Sketch variants:

### 1. **s-bubble** - Standard Bubble
- `loader.c` - user-space loader program
- `ebpf.c` - eBPF kernel program
- `common.h` - Shared header definitions
- `fasthash.h` - fasthash functions
- `Makefile` - Build configuration

### 2. **p-bubble** - Persistent Bubble
Contains the same file structure with persistent memory optimizations.

### 3. **t-bubble** - Tail Call Bubble
Implements tail call optimizations for better performance.

### 4. **m-bubble** - Map Sharding Bubble
Uses map sharding techniques for improved scalability.

### 5. **libpcap-bubble** - User-space Variants
- **u-bubble**: User-space Bubble Sketch implementation
- **libpcap-bubble**: User-space variant processing live interface traffic

## Building and Running

### For eBPF Variants (s-bubble, p-bubble, t-bubble, m-bubble)

Navigate to any variant folder and use the following commands:

#### Clean build artifacts:
```bash
make clean
```

#### Compile the project:
```bash
make
```

#### Run the loader:
```bash
make run
```

#### Run with custom interface:
```bash
make run IFACE=<interface_name> SKETCH=bubble
```

### Testing with Network Traffic

1. **Start the eBPF program** in one terminal:
   ```bash
   make run
   ```

2. **Replay PCAP traffic** from another terminal:
   ```bash
   sudo tcpreplay --intf1=veth-send --topspeed 1.pcap > tcpreplay_output.txt
   ```
   
   **Note**: Ensure `make run` is executing before starting tcpreplay. Replace `1.pcap` with your PCAP file (obtained from `.dat` files in `dats/` directory).

3. **Stop the program** using `Ctrl+C` after tcpreplay completes.

4. **Analyze results**: The output will be saved in `sketch_output.txt`. Run the accuracy calculation script:
   ```bash
   python3 accuracy_calc.py
   ```

## User-space Bubble Sketch (libpcap-bubble)

The `libpcap-bubble` folder contains implementations that run in user-space:

### Compilation:
```bash
cd libpcap-bubble
gcc BubbleSketch_pcap.c -o BubbleSketch_pcap -lpcap
```

### Execution:
```bash
./BubbleSketch_pcap <interface> [-k top_k] [-m memory_kb] [-t duration_sec]
```

**Parameters:**
- `<interface>`: Network interface to monitor (e.g., `eth0`, `veth-send`)
- `-k top_k`: Number of top heavy hitters to track (optional)
- `-m memory_kb`: Memory size in KB (optional)
- `-t duration_sec`: Duration to capture traffic in seconds (optional)

## Makefile Commands Summary

Each variant's Makefile supports:
- **Target architecture configuration**: Automatically detects and configures for the host machine
- **eBPF compilation**: Compiles `.c` files to eBPF bytecode
- **Skeleton generation**: Creates header files for eBPF program loading
- **Loader compilation**: Uses Clang to compile the user-space loader
- **Execution**: Runs the complete eBPF program

## Output and Metrics

After running the eBPF programs:
- **sketch_output.txt**: Contains the raw output from the Bubble Sketch algorithm
- **tcpreplay_output.txt**: Contains tcpreplay statistics
- **accuracy_calc.py**: Calculates precision, recall, and other accuracy metrics

## Workflow Summary

```
1. Setup veth pair (one-time)
2. Choose variant directory (s-bubble, p-bubble, t-bubble, or m-bubble)
3. make clean && make
4. make run (terminal 1)
5. tcpreplay PCAP file (terminal 2)
6. Ctrl+C to stop eBPF program
7. python3 accuracy_calc.py
```

## Notes

- Ensure all commands are run with appropriate permissions (some may require `sudo`)
- The veth pair setup is required only once unless the network configuration changes
- PCAP files should be prepared from `.dat` files in the `dats/` directory
- Each variant implements different optimization strategies for heavy hitter detection

## Troubleshooting

- If compilation fails, ensure all dependencies (libbpf, clang, kernel headers) are installed
- For permission errors, run with `sudo` where necessary
- Verify the veth interfaces exist with `ip link show` before running tests
