# POODLE Attack Proof of Concept

A complete demonstration environment for CVE-2014-3566 (POODLE - Padding Oracle On Downgraded Legacy Encryption) using Docker containers.

## Overview

This project provides an isolated environment to demonstrate the POODLE attack against SSLv3. The environment consists of three Docker containers simulating a realistic attack scenario.

### Architecture

- **Client Container**: Generates SSLv3 traffic with authentication cookies
- **Server Container**: Apache web server configured to accept only SSLv3 connections with CBC ciphers
- **Attacker Container**: Tools for traffic capture and padding oracle exploitation

## Prerequisites

- Docker and Docker Compose installed
- Kali Linux (or any Linux distribution)
- Minimum 2GB RAM
- 10GB free disk space

## Installation

### 1. Build Containers

```bash
docker-compose build --no-cache
```

### 2. Start Environment

```bash
docker-compose up -d
```

### 3. Verify Containers

```bash
docker-compose ps
```

All three containers (poodle_vulnerable_server, poodle_client, poodle_attacker) should be running.

## Running the Attack

### Automated Attack

Execute the complete attack demonstration:

```bash
./run-complete-attack.sh
```

The script will:

1. Start victim traffic generation
2. Capture encrypted SSLv3 traffic for 60 seconds
3. Present three attack options:
   - Option 1: Realistic CVE-2014-3566 (with block alignment and padding injection)
   - Option 2: Visual demonstration (simplified step-by-step)
   - Option 3: Technical exploit (theory and analysis)

### Manual Attack Steps

#### Step 1: Start Client Traffic

```bash
docker exec -d poodle_client /client-scripts/generate-traffic.sh
```

#### Step 2: Capture Traffic

Identify the Docker bridge interface:

```bash
ip link show | grep br-
```

Capture packets (replace INTERFACE with actual bridge name):

```bash
sudo tcpdump -i INTERFACE -w captures/poodle_attack.pcap \
  "host 172.25.0.20 and host 172.25.0.10 and port 443"
```

#### Step 3: Run Exploit

Choose one of the attack scripts:

```bash
# Realistic attack with full padding oracle demonstration
docker exec -it poodle_attacker python /attack/realistic-poodle-attack.py

# Visual demonstration
docker exec -it poodle_attacker python /attack/visual-poodle-attack.py

# Technical analysis
docker exec poodle_attacker python /attack/poodle-exploit.py /captures/poodle_attack.pcap
```

## Attack Details

### Target Cookie

The server generates a JWT-like authentication token:

```json
{
    "user_id": 1337,
    "username": "admin",
    "role": "administrator",
    "issued_at": 1234567890,
    "expires_at": 1234571490
}
```

This is base64-encoded and signed, resulting in a cookie approximately 150 bytes in length.

### Attack Flow

1. **Reconnaissance**: Verify target supports SSLv3
2. **Traffic Analysis**: Capture encrypted SSL records to estimate cookie size
3. **Block Size Detection**: Determine cipher block size from SSL handshake
4. **Cookie Alignment**: Calculate padding required to position target bytes at block boundaries
5. **Padding Oracle**: Exploit SSLv3 padding validation weakness
6. **Decryption**: Decrypt cookie byte-by-byte using server responses as oracle

### Expected Duration

- Block size detection: 5-10 seconds
- Full cookie decryption: 5-10 minutes (approximately 128 requests per byte)
- Total attack time: 10-15 minutes

## Network Configuration

### Container Network

All containers run on a custom Docker bridge network (172.25.0.0/16):

- Server: 172.25.0.10
- Client: 172.25.0.20
- Attacker: 172.25.0.30

### Port Mapping

- Host port 8443 maps to server port 443

## Verification

### Test SSLv3 Support

```bash
docker exec poodle_attacker openssl s_client -connect 172.25.0.10:443 -ssl3 </dev/null
```

Expected output should show "Protocol: SSLv3" and a CBC cipher.

### Check Cookie Generation

```bash
docker exec poodle_attacker curl -k --sslv3 https://172.25.0.10/ -I
```

Should display multiple Set-Cookie headers including auth_token.

### Verify Traffic Capture

```bash
docker logs poodle_client --tail 10
```

Should show successful HTTPS requests every 2 seconds.

## Troubleshooting

### Containers Not Starting

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### No Cookies in Response

Verify PHP is executing:

```bash
docker exec poodle_vulnerable_server ls -la /var/www/html/
docker exec poodle_vulnerable_server apache2ctl -t
```

### Zero Packets Captured

Verify correct bridge interface:

```bash
ip link show | grep br-
docker network inspect poodle-poc_poodle_network
```

Capture on the correct bridge interface, not docker0.

### SSLv3 Not Supported Error

Confirm server configuration:

```bash
docker exec poodle_vulnerable_server cat /etc/apache2/sites-enabled/default-ssl.conf | grep SSLProtocol
```

Should show: `SSLProtocol -all +SSLv3`

## Security Considerations

**WARNING**: This environment is intentionally vulnerable. Use only in isolated networks for educational purposes.

- Never deploy SSLv3 in production environments
- This PoC demonstrates why SSLv3 must be disabled
- Attack requires man-in-the-middle position
- Real-world exploitation requires additional conditions (active browsing, JavaScript execution)

## Technical Details

### CVE-2014-3566

- **CVSS v3.1 Score**: 3.4 (Low)
- **CVSS v2.0 Score**: 4.3 (Medium)
- **Attack Vector**: Network
- **Attack Complexity**: High
- **Impact**: Confidentiality breach (session cookies, authentication tokens)

### Vulnerability

SSLv3 uses MAC-then-Encrypt with unauthenticated CBC padding. The protocol validates padding before MAC verification, creating a padding oracle that leaks plaintext information.

### Mitigation

1. Disable SSLv3 on all servers
2. Use TLS 1.2 or higher
3. Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)
4. Enable TLS_FALLBACK_SCSV (RFC 7507)

## File Structure

```
.
├── README.md                       # This file
├── docker-compose.yml              # Container orchestration
├── Dockerfile                      # Server container definition
├── Dockerfile.client               # Client container definition
├── Dockerfile.attacker             # Attacker container definition
├── ssl-vulnerable.conf             # Apache SSLv3 configuration
├── run-complete-attack.sh          # Automated attack script
├── www/
│   ├── index.php                   # Vulnerable web application
│   └── api.php                     # API endpoint
├── client-scripts/
│   └── generate-traffic.sh         # Traffic generator
├── attacker-scripts/
│   ├── realistic-poodle-attack.py  # Full CVE-2014-3566 demonstration
│   ├── visual-poodle-attack.py     # Visual step-by-step demonstration
│   └── poodle-exploit.py           # Technical analysis tool
└── docs/
    └── poodle-attack-diagram.svg   # Attack flow diagram
```

## References

- CVE-2014-3566: https://nvd.nist.gov/vuln/detail/CVE-2014-3566
- Original POODLE paper: https://www.openssl.org/~bodo/ssl-poodle.pdf
- RFC 7507 (TLS_FALLBACK_SCSV): https://tools.ietf.org/html/rfc7507

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Educational Use Only**: This software is designed for educational and research purposes only. It intentionally implements vulnerable configurations to demonstrate security vulnerabilities. Users must only deploy this software in isolated, controlled environments and must not use it for malicious purposes or on systems they do not own or have explicit permission to test.

## Authors

- [@Pjnp5](https://github.com/Pjnp5)
- [@Rita-Silva04](https://github.com/Rita-Silva04)
- [@odraude23](https://github.com/odraude23)

This project was developed for the first assignment of Analysis and Exploration of Vulnerabilities as a proof of concept for educational purposes.
