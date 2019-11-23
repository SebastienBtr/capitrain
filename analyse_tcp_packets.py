import pyshark
import socket
import os
from db import connectToCluster, saveOnePacket

LISTENED_IP = os.getenv('LISTENED_IP')

# Analyze a pkt to save it in the good key of our date structure
def analyse_packets(pkt):
    if ('TCP' in pkt and 'IP' in pkt):
        # time when the packet was received
        timestamp = float(pkt.sniff_timestamp)

        # If we already have the stream in the dict or not
        if (pkt.tcp.stream not in packet_dict):
            # Get the remote ip of the stream
            ip = pkt.ip.dst if pkt.ip.dst != LISTENED_IP else pkt.ip.src
            save_new_stream(pkt.tcp.stream, timestamp, ip, pkt)
        else:
            time_delta = float(pkt.tcp.time_delta)
            average_delta = packet_dict[pkt.tcp.stream]['averageDelta']

            # Based on the average delta time we split the packets
            if (average_delta != 0 and time_delta > average_delta * 3):
                push_data(pkt.tcp.stream)
                del packet_dict[pkt.tcp.stream]
            else:
                # Update the delta average
                sum_delta = packet_dict[pkt.tcp.stream]['sumDelta'] + time_delta
                number_of_packets = packet_dict[pkt.tcp.stream]['numberOfPackets'] + 1
                average_delta = sum_delta / number_of_packets

                # Save the new data of the stream
                packet_dict[pkt.tcp.stream]['endTime'] = timestamp
                packet_dict[pkt.tcp.stream]['sumDelta'] = sum_delta
                packet_dict[pkt.tcp.stream]['numberOfPackets'] = number_of_packets
                packet_dict[pkt.tcp.stream]['averageDelta'] = average_delta
                packet_dict[pkt.tcp.stream]['totalMbSize'] += get_packet_size(
                    pkt)


# Get the size in MB of a packet
def get_packet_size(pkt):
    return int(pkt.length.raw_value, 16) * 0.000001

# Save a new stream and its first packet in the dict
def save_new_stream(stream_id, timestamp, ip, pkt):
    domain = reverse_dns(ip)
    packet_dict[stream_id] = {
        'sumDelta': 0,
        'averageDelta': 0,
        'ip': ip,
        'domain': domain,
        'numberOfPackets': 1,
        'totalMbSize': get_packet_size(pkt),
        'startTime': timestamp,
        'endTime': timestamp,
    }

# Send a group of packets that seems to be together to the DB
def push_data(key):
    print('Push data: ' + str(packet_dict[key]))
    saveOnePacket(packet_dict[key])

# Reverse DNS a remote IP
def reverse_dns(ip):
    try:
        reversed_dns = socket.gethostbyaddr(ip)
        return reversed_dns[0]
    except:
        return ""


# Data structure
""" packet_dict = {
  stream_index: {
    'sumDelta': 0,
    'averageDelta': 0,
    'ip': ip,
    'domain': string,
    'numberOfPackets': 1,
    'totalMbSize': size in MB,
    'startTime': timestamp,
    'endTime': timestamp,
  }
} """
packet_dict = {}

# Connect to MongoDB cluster
connectToCluster()

cap = pyshark.FileCapture('capture.pcap')
cap.apply_on_packets(analyse_packets)

# We push_data all the remaining streams in packet_dict
for key in packet_dict:
    push_data(key)

print('done')
