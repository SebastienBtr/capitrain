from datetime import date
import socket
import time
import threading

# Data structure
""" packet_dict = {
  stream_index: {
    'lastTime': datetime,
    'totalDiffTime': microseconds duration
    'averageTime': microseconds duration,
    'ip': ip,
    'numberOfPackets': 0,
    'totalMbSize': 0,
    'startTime': datetime,
    'domain': ''
  }
} """
packet_dict = {}
""" timers = {
  stream_index: Timer
} """
timers = {}


def read_packet(pkt):
    if ('TCP' in pkt and 'IP' in pkt):
        last_timestamp = float(pkt.sniff_timestamp)
        # If we already have the stream in the dict or not
        if (pkt.tcp.stream not in packet_dict):
            # Get the remote ip of the stream
            host_name = socket.gethostname()
            my_ip = socket.gethostbyname(host_name)
            ip = pkt.ip.dst if pkt.ip.dst != my_ip else pkt.ip.src

            save_new_stream(pkt.tcp.stream, last_timestamp, ip, pkt)
        else:
            if (pkt.tcp.stream in timers):
                timers[pkt.tcp.stream].cancel()

            #last_time = packet_dict[pkt.tcp.stream]['lastTime']
            #average_time = packet_dict[pkt.tcp.stream]['averageTime']
            # We don't use pkt.tcp.time_delta because it's less accurate
            #dif = abs(last_timestamp - last_time)

            # Update the average time and save the new packet
            #total_diff_time = packet_dict[pkt.tcp.stream]['totalDiffTime'] + dif
            #number_of_packets = packet_dict[pkt.tcp.stream]['numberOfPackets'] + 1
            #average_time = total_diff_time / number_of_packets

            # Save the new data
            packet_dict[pkt.tcp.stream]['lastTime'] = last_timestamp
            #packet_dict[pkt.tcp.stream]['totalDiffTime'] = total_diff_time
            #packet_dict[pkt.tcp.stream]['averageTime'] = average_time
            packet_dict[pkt.tcp.stream]['numberOfPackets'] += 1
            packet_dict[pkt.tcp.stream]['totalMbSize'] += get_packet_size(
                pkt)

            # If we think the packet is too far from the previous one
            # according to the average time betewen packets of this stream
            def timer_callback():
                return push_data(pkt.tcp.stream)
            
            stream_timer = threading.Timer(5, timer_callback)
            timers[pkt.tcp.stream] = stream_timer
            stream_timer.start()


def get_packet_size(pkt):
    return float(pkt.tcp.len) * 0.000001


def save_new_stream(key, last_time, ip, pkt):
    domain = reverse_dns(ip)
    packet_dict[key] = {
        'lastTime': last_time,
        #'totalDiffTime': 0,
        #'averageTime': 0,
        'ip': ip,
        'domain': domain,
        'numberOfPackets': 1,
        'totalMbSize': get_packet_size(pkt),
        'startTime': last_time,
    }


def push_data(key):
    print('push data===================================')
    # save in DB
    del packet_dict[key]
    del timers[key]


def reverse_dns(ip):
    try:
        reversed_dns = socket.gethostbyaddr(ip)
        return reversed_dns[0]
    except:
        print("No DNS found")
        return ""
