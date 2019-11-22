import pyshark
import read_packets

capture = pyshark.LiveCapture(
    interface='en0', output_file="./capture.pcap")


def print_callback(pkt):
    read_packets.read_packet(pkt)


capture.apply_on_packets(print_callback)
capture.sniff()
