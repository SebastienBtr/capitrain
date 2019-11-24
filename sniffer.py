import pyshark
import os

SNIFFER_TIMEOUT = int(os.getenv('SNIFFER_TIMEOUT'))
LISTENED_IP = os.getenv('LISTENED_IP')
INTERFACE = os.getenv('INTERFACE')

filter = "tcp&&(ip.dst==" + LISTENED_IP + "||ip.src==" + LISTENED_IP + ")"

capture = pyshark.LiveCapture(
    interface=INTERFACE, output_file="./capture.pcap", display_filter=filter)

capture.sniff(timeout=SNIFFER_TIMEOUT)
