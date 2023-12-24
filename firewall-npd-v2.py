import os
import time
import signal
import socket
import struct

# Function to Unpack Ethernet Frame
def ethernet_frame(data):
    dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to Return Properly Formatted MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02X}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Function to Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Function to Return Properly Formatted IPv4 Address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Function to Unpack ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Function to Unpack TCP Segment
def tcp_segment(data):
    (src_port, dst_port, _, _, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dst_port, 'TCP', data[offset:]

# Function to Unpack UDP Segment
def udp_segment(data):
    src_port, dst_port = struct.unpack('! H H', data[:4])
    return src_port, dst_port, 'UDP', data[8:]

def save_capture():
    with open("log.txt", "a") as log_file:
        log_file.write("\n".join(capture_log))
    print("Capture Saved as log.txt Successfully.")

def signal_handler(sig, frame):
    print("\nCTRL+C detected. Do you want to save the capture to log.txt? (Y/N):")
    user_input = input().strip().lower()
    if user_input.lower() == "y" or user_input.lower() == "yes":
        save_capture()  # Call the save_capture function
    elif user_input.lower() == "n" or user_input.lower() == "no":
        print("Capture not saved.")
    else:
        print("Invalid input. Capture not saved.")
    exit(0)

# Packet Monitoring Function
def monitor():
    global capture_log  # Declare capture_log as a global variable

    capture_log = []

    # Check if log.txt exists, and create it if not
    if not os.path.isfile("log.txt"):
        with open("log.txt", "w") as log_file:
            log_file.write("Packet Log:\n")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Register the CTRL+C signal handler
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        dst_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        log_message = '\nTimestamp: {}'.format(timestamp)
        log_message += '\n\tSource MAC: {}\n\tDestination MAC: {}'.format(src_mac, dst_mac)

        # Log IPv4 information
        if eth_proto == 8:
            (version, _, _, proto, src, target, data) = ipv4_packet(data)
            log_message += '\n\tSource IP: {}\n\tDestination IP: {}'.format(src, target)

            # Log TCP information
            if proto == 6:
                src_port, dst_port, protocol, _ = tcp_segment(data)
                log_message += '\n\tSource Port: {}\n\tDestination Port: {}\n\tProtocol: {}'.format(
                    src_port, dst_port, protocol)

            # Log UDP information
            elif proto == 17:
                src_port, dst_port, protocol, _ = udp_segment(data)
                log_message += '\n\tSource Port: {}\n\tDestination Port: {}\n\tProtocol: {}'.format(
                    src_port, dst_port, protocol)

        capture_log.append(log_message)
        print(log_message)

# Main Function
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
