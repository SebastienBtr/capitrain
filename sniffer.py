import environment
import pyshark
import os
import argparse

# Check if we have the necessaries environment variables
environment.check_sniffer_env()

# Arguments available
parser = argparse.ArgumentParser()
parser.add_argument(
    '--outputFile', '-of', default="capture", help='The name of the pcap output file, default: capture')
parser.add_argument(
    '--timeout', '-t', default=None, help='Timeout in seconds of the sniffer, default: None')
parser.add_argument(
    '--protocols', '-p', default="tcp", help='Protocols to capture, possible values : tcp, udp and both, default: tcp')
args = parser.parse_args()

# env var
LISTENED_IP = os.getenv('LISTENED_IP')
INTERFACE = os.getenv('INTERFACE')
LOCAL_IP = os.getenv('LOCAL_IP')

# Sets output file name
output_file = args.outputFile + ".pcap"

# Determines protocols to filter
protocols = ""
if args.protocols is "udp":
    protocols = "udp&&"
elif args.protocols is "both":
    protocols = "tcp&&udp&&"
else:
    protocols = args.protocols
filter = protocols + "(ip.src!=" + LOCAL_IP + "&&ip.src!=" + LISTENED_IP + ")"

capture = pyshark.LiveCapture(
    interface=INTERFACE, output_file=output_file, display_filter=filter)

# Launch the capture
if args.timeout is None:
    capture.sniff()
else:
    capture.sniff(timeout=int(args.timeout))
