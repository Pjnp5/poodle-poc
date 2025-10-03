#!/bin/bash

echo "================================================"
echo "POODLE PoC - Client Traffic Generator"
echo "================================================"
echo ""

# Server details
SERVER_IP="172.25.0.10"
SERVER_PORT="443"
SERVER_URL="https://${SERVER_IP}:${SERVER_PORT}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Client Configuration:${NC}"
echo "  Client IP: $(hostname -i)"
echo "  Target Server: ${SERVER_IP}:${SERVER_PORT}"
echo ""

# Check if server is reachable
echo -e "${GREEN}[1] Checking if server is reachable...${NC}"
if ! ping -c 1 ${SERVER_IP} &> /dev/null; then
    echo -e "${RED}[ERROR] Cannot reach server at ${SERVER_IP}${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Server is reachable${NC}"
echo ""

# First request to get cookies
echo -e "${GREEN}[2] Making initial request to get cookies...${NC}"
COOKIE_FILE="/tmp/cookies.txt"

curl -k --sslv3 -c ${COOKIE_FILE} ${SERVER_URL}/ \
    -o /dev/null -s -w "HTTP Status: %{http_code}\n"

if [ -f ${COOKIE_FILE} ]; then
    echo -e "${GREEN}[OK] Cookies saved to ${COOKIE_FILE}${NC}"
    echo ""
    echo "Cookies received:"
    cat ${COOKIE_FILE} | grep -v "^#"
else
    echo -e "${RED}[ERROR] No cookies received${NC}"
fi
echo ""

# Generate continuous traffic
echo -e "${GREEN}[3] Starting continuous traffic generation...${NC}"
echo "Sending requests every 2 seconds..."
echo "Press CTRL+C to stop"
echo ""

REQUEST_COUNT=0

while true; do
    REQUEST_COUNT=$((REQUEST_COUNT + 1))

    TIMESTAMP=$(date +"%H:%M:%S")

    # Send request with cookies
    RESPONSE=$(curl -k --sslv3 \
        -b ${COOKIE_FILE} \
        -X POST \
        -d "action=heartbeat&count=${REQUEST_COUNT}" \
        ${SERVER_URL}/api.php \
        -s -w "\nHTTP_CODE:%{http_code}" 2>&1)

    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)

    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "[${TIMESTAMP}] ${GREEN}[OK]${NC} Request #${REQUEST_COUNT} - Status: ${HTTP_CODE}"
    else
        echo -e "[${TIMESTAMP}] ${RED}[ERROR]${NC} Request #${REQUEST_COUNT} - Status: ${HTTP_CODE}"
    fi

    sleep 2
done
