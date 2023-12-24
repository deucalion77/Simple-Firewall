import os
import time
import signal
import socket
import struct
from prettytable import PrettyTable

def ethernet_frame(data):
    dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(format(x, '02x') for x in bytes_addr).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dst_port, _, _, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dst_port, 'TCP', data[offset:]

def udp_segment(data):
    src_port, dst_port = struct.unpack('! H H', data[:4])
    return src_port, dst_port, 'UDP', data[8:]

def save_capture():
    with open("log.txt", "a") as log_file:
        log_file.write("\n".join(capture_log))
    print("Capture Saved as log.txt Successfully.")

def signal_handler(sig, frame):
    save_capture()
    exit(0)

def monitor():
    global capture_log

    capture_log = []

    if not os.path.isfile("log.txt"):
        with open("log.txt", "w") as log_file:
            log_file.write("Packet Log:\n")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        dst_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        log_message = '|: {}'.format(timestamp)
        log_message += ', |: {}, |: {}'.format(src_mac, dst_mac)

        if eth_proto == 8:
            (version, _, _, proto, src, target, data) = ipv4_packet(data)
            log_message += ', |: {}, |: {}'.format(src, target)

            if proto == 6:
                src_port, dst_port, protocol, _ = tcp_segment(data)
                log_message += ', | : {}, | : {}, | : {}'.format(
                    src_port, dst_port, protocol)
            elif proto == 17:
                src_port, dst_port, protocol, _ = udp_segment(data)
                log_message += ', | : {}, | : {}, | : {}'.format(
                    src_port, dst_port, protocol)

        capture_log.append(log_message)
        print(log_message)

        # Display in horizontal table format
        table = PrettyTable()
        table.field_names = ["Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"]

        for log_entry in capture_log:
            log_data = [item.strip() for item in log_entry.split(',')]
            if len(log_data) == 8:
                table.add_row(log_data)

        print(table)

def start_monitoring():
    print("Do you want to start packet monitoring? (Y/N):")
    user_input = input().strip().lower()
    if user_input == "y" or user_input == "yes":
        monitor()
    elif user_input == "n" or user_input == "no":
        print("Packet monitoring not started.")
    else:
        print("Invalid input. Packet monitoring not started.")

if __name__ == "__main__":
    start_monitoring()
