import pyshark
import socket

# Analyze a pkt to save it in the good key of our date structure
def analyze_packets(pkt):
    if ('TCP' in pkt and 'IP' in pkt):
        # time when the packet was received
        timestamp = float(pkt.sniff_timestamp)
        # If we already have the stream in the dict or not
        if (pkt.tcp.stream not in packet_dict):
            # Get the remote ip of the stream
            ip = pkt.ip.dst if pkt.ip.dst != my_ip else pkt.ip.src
            save_new_stream(pkt.tcp.stream, timestamp, ip, pkt)
        else:
            time_delta = float(pkt.tcp.time_delta)
            average_delta = packet_dict[pkt.tcp.stream]['averageDelta']

            # Based on the average delta time we split the packets
            if (average_delta != 0 and time_delta > average_delta * 3):
                push_data(pkt.tcp.stream)
            else:
                # Update the delta average
                sum_delta = packet_dict[pkt.tcp.stream]['sumDelta'] + time_delta
                number_of_packets = packet_dict[pkt.tcp.stream]['numberOfPackets'] + 1
                average_delta = sum_delta / number_of_packets
                print(time_delta)
                print(average_delta)

                # Save the new data of the stream
                packet_dict[pkt.tcp.stream]['endTime'] = timestamp
                packet_dict[pkt.tcp.stream]['sumDelta'] = sum_delta
                packet_dict[pkt.tcp.stream]['numberOfPackets'] = number_of_packets
                packet_dict[pkt.tcp.stream]['averageDelta'] = average_delta
                packet_dict[pkt.tcp.stream]['totalMbSize'] += get_packet_size(
                    pkt)


# Get the size in MB of a packet
def get_packet_size(pkt):
    return float(pkt.tcp.len) * 0.000001

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
    print('push data===================================')
    # TODO: save in DB
    del packet_dict[key]

# Reverse DNS a remote IP
def reverse_dns(ip):
    # TODO: find a better reverse DNS
    try:
        reversed_dns = socket.gethostbyaddr(ip)
        return reversed_dns[0]
    except:
        print("No DNS found")
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

# Get host IP
host_name = socket.gethostname()
my_ip = socket.gethostbyname(host_name)

cap = pyshark.FileCapture('capture.pcap')
cap.apply_on_packets(analyze_packets)

# TODO: do a push_data for all the remaining streams in packet_dict
print('done')