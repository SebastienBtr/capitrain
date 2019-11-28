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
INTERFACE = os.getenv('INTERFACE')
LISTENED_IP = os.getenv('LISTENED_IP')
LOCAL_IP = os.getenv('LOCAL_IP')
LISTENED_IPV6 = os.getenv('LISTENED_IPV6')
LOCAL_IPV6 = os.getenv('LOCAL_IPV6')

# Sets output file name
output_file = args.outputFile + ".pcap"

# Determines protocols to filter
protocols = ""
if args.protocols == "udp":
    protocols = "udp&&"
elif args.protocols == "both":
    protocols = "tcp&&udp&&"
else:
    protocols = "tcp&&"

# Creates filter for sniffing
filter = protocols + "(ip.src!=" + LOCAL_IP + "&&ip.src!=" + LISTENED_IP + ")"

# Modifies filter to add IPv6 if necessary
if (LISTENED_IPV6 is not None) and (LOCAL_IPV6 is not None):
    filter = filter + "&&(ipv6.src!=" + LOCAL_IPV6 + \
        "&&ipv6.src!=" + LISTENED_IPV6 + ")"

capture = pyshark.LiveCapture(
    interface=INTERFACE, output_file=output_file, display_filter=filter)

# Launch the capture
if args.timeout is None:
    capture.sniff()
else:
    capture.sniff(timeout=int(args.timeout))
