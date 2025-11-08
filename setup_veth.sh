#!/bin/bash
# setup_veth.sh - Create virtual ethernet pair for eBPF testing

set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Setting up veth pair for eBPF testing ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run as root (use sudo)${NC}"
    exit 1
fi

# Clean up existing veth pair if it exists
if ip link show veth-send &> /dev/null; then
    echo -e "${YELLOW}Removing existing veth-send...${NC}"
    ip link delete veth-send
fi

if ip link show veth-recv &> /dev/null; then
    echo -e "${YELLOW}Removing existing veth-recv...${NC}"
    ip link delete veth-recv
fi

# Create veth pair
echo "Creating veth pair..."
ip link add veth-send type veth peer name veth-recv

# Set MAC addresses to match PCAP generation script
echo "Setting MAC addresses..."
ip link set dev veth-send address ea:d9:d9:8f:0d:4f
ip link set dev veth-recv address 1a:43:4f:ac:3f:05

# Bring interfaces up
echo "Bringing interfaces up..."
ip link set veth-send up
ip link set veth-recv up

# Assign IP addresses
echo "Assigning IP addresses..."
ip addr add 10.0.0.1/24 dev veth-send
ip addr add 10.0.0.2/24 dev veth-recv

# Verify setup
echo -e "\n${GREEN}=== Setup Complete ===${NC}"
echo "veth-send: 10.0.0.1/24 (MAC: ea:d9:d9:8f:0d:4f)"
echo "veth-recv: 10.0.0.2/24 (MAC: 1a:43:4f:ac:3f:05)"

echo -e "\n${GREEN}Verification:${NC}"
ip link show veth-send | grep -E "veth-send|link/ether"
ip link show veth-recv | grep -E "veth-recv|link/ether"

echo -e "\n${GREEN}Next steps:${NC}"
echo "1. Attach XDP to veth-recv:"
echo "   sudo ./pcap_metrics_analyzer veth-recv packets_from_dat.pcap 1000"
echo ""
echo "2. In another terminal, replay packets:"
echo "   sudo tcpreplay --intf1=veth-send --topspeed packets_from_dat.pcap"
echo ""
echo "To remove veth pair later:"
echo "   sudo ip link delete veth-send"
