import pyshark
import os

SNIFFER_TIMEOUT = int(os.getenv('SNIFFER_TIMEOUT'))
LISTENED_IP = os.getenv('LISTENED_IP')
INTERFACE = os.getenv('INTERFACE')
VPN_IP = os.getenv('VPN_IP')

filter = "tcp&&(ip.dst==" + VPN_IP + "||ip.src==" + LISTENED_IP + ")"

capture = pyshark.LiveCapture(
    interface=INTERFACE, output_file="./capture.pcap", display_filter=filter)

capture.sniff(timeout=SNIFFER_TIMEOUT)
