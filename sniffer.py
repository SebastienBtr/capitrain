import environment
import pyshark
import os
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('--outputFile', '-of',
                    help='The name of the pcap output file, default: capture')
parser.add_argument(
    '--timeout', '-t', help='Timeout in seconds of the sniffer, default: no timeout')

args = parser.parse_args()

LISTENED_IP = os.getenv('LISTENED_IP')
INTERFACE = os.getenv('INTERFACE')
LOCAL_IP = os.getenv('LOCAL_IP')

filter = "tcp&&(ip.dst==" + LOCAL_IP + "||ip.src==" + LISTENED_IP + ")"
output_file = "capture.pcap" if args.outputFile is None else args.outputFile + ".pcap"

capture = pyshark.LiveCapture(
    interface=INTERFACE, output_file=output_file, display_filter=filter)

if args.timeout is None:
    capture.sniff()
else:
    capture.sniff(timeout=args.timeout)
