import pyshark

capture = pyshark.LiveCapture(
    interface='en0', output_file="./capture.pcap")


def print_callback(pkt):
    print(pkt)


capture.apply_on_packets(print_callback)
capture.sniff()
