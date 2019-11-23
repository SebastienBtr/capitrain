import pyshark
import os

SNIFFER_TIMEOUT = os.getenv('SNIFFER_TIMEOUT')
LISTENED_IP = os.getenv('LISTENED_IP')

filter = "tcp&&(ip.dst==" + LISTENED_IP + "||ip.src==" + LISTENED_IP + ")"

# TODO: get interface from env variable ?
capture = pyshark.LiveCapture(
    interface="en0", output_file="./capture.pcap", display_filter=filter)


def print_callback(pkt):
    print(pkt)


capture.apply_on_packets(print_callback, timeout=SNIFFER_TIMEOUT)
capture.sniff()
