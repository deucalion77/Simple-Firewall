import os
import time
import signal
import socket
import struct
from prettytable import PrettyTable
from netfilterqueue import NetfilterQueue
from scapy.all import *
import json

DictOfPackets = {}  # Initialize a dictionary to store packet information
AutoBlockedIPs = set()  # Keep track of IPs that have been auto-blocked

##This Code is build for the Network Programming Assingment and full owership is belongs to the A.K.N.Anupama
# Function to Unpack Ethernet Frame
def ethernet_frame(data):
    dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Function to Return Properly Formatted MAC Address
def get_mac_addr(bytes_addr):
    return ':'.join(format(x, '02x') for x in bytes_addr).upper()

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

# Function to Save Packet Capture
def save_capture():
    with open("analize.txt", "a") as log_file:
        log_file.write("\n".join(capture_log))
    print("Capture Saved as analize.txt Successfully.")

# Signal Handler for CTRL+C
def signal_handler(sig, frame):
    print("Do you want to save the capture to analize.txt? (Y/N):")
    user_input = input().strip().lower()
    if user_input.lower() == "y" or user_input.lower() == "yes":
        save_capture()
    elif user_input.lower() == "n" or user_input.lower() == "no":
        print("Data is not saved.")
    else:
        print("Invalid input. Data was not saved.")
    exit(0)

# Packet Monitoring Function
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

# Function to Unpack IPSec Packet
def ipsec_packet(data):
    # Add IPSec packet parsing logic here
    # Return relevant information about IPSec packet
    pass

# Function to Run IPSec Functionality

def IPSec():
    DictOfPackets = {}  # Initialize a dictionary to store packet information
    AutoBlockedIPs = set()  # Keep track of IPs that have been auto-blocked

    ListOfBannedIpAddr = [] 
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10  # sec
    PacketThreshold = 100    
    BlockPingAttacks = True

    def save_rules():
        # Save the updated rules to the firewallrules.json file
        rules = {
            "ListOfBannedIpAddr": ListOfBannedIpAddr,
            "ListOfBannedPorts": ListOfBannedPorts,
            "ListOfBannedPrefixes": ListOfBannedPrefixes,
            "TimeThreshold": TimeThreshold,
            "PacketThreshold": PacketThreshold,
            "BlockPingAttacks": str(BlockPingAttacks),
        }

        with open("firewallrules.json", "w") as f:
            json.dump(rules, f, indent=2)

    def release_ip(ip):
        # Release the specified IP address
        if ip in ListOfBannedIpAddr:
            ListOfBannedIpAddr.remove(ip)
            print(f"IP address {ip} released from the ban list.")
            save_rules()

    try:
        f = open("firewallrules.json", "r")
        y = json.load(f)
        f.close()
        if "ListOfBannedIpAddr" in y:
            if type(y["ListOfBannedIpAddr"]) == list:
                ListOfBannedIpAddr = y["ListOfBannedIpAddr"]
            else:
                print("Invalid ListOfBannedIpAddr in rule file. Defaulting to []")
                ListOfBannedIpAddr = []
        else:
            print("ListOfBannedIpAddr missing in rule file. Defaulting to []")
            ListOfBannedIpAddr = []

        if "ListOfBannedPorts" in y:
            if type(y["ListOfBannedPorts"]) == list:
                ListOfBannedPorts = y["ListOfBannedPorts"]
            else:
                print("Invalid ListOfBannedPorts in rule file. Defaulting to []")
                ListOfBannedPorts = []
        else:
            print("ListOfBannedPorts missing in rule file. Defaulting to []")
            ListOfBannedPorts = []

        if "ListOfBannedPrefixes" in y:
            if type(y["ListOfBannedPrefixes"]) == list:
                ListOfBannedPrefixes = y["ListOfBannedPrefixes"]
            else:
                print("Invalid ListOfBannedPrefixes in rule file. Defaulting to []")
                ListOfBannedPrefixes = []
        else:
            print("ListOfBannedPrefixes missing in rule file. Defaulting to []")
            ListOfBannedPrefixes = []

        if "TimeThreshold" in y:
            if type(y["TimeThreshold"]) == int:
                TimeThreshold = y["TimeThreshold"]
            else:
                print("Invalid TimeThreshold in rule file. Defaulting to 10")
                TimeThreshold = 10
        else:
            print("TimeThreshold missing in rule file. Defaulting to 10")
            TimeThreshold = 10

        if "PacketThreshold" in y:
            if type(y["PacketThreshold"]) == int:
                PacketThreshold = y["PacketThreshold"]
            else:
                print("Invalid PacketThreshold in rule file. Defaulting to 100")
                PacketThreshold = 100
        else:
            print("PacketThreshold missing in rule file. Defaulting to 100")
            PacketThreshold = 100

        if "BlockPingAttacks" in y:
            if y["BlockPingAttacks"] == "True" or y["BlockPingAttacks"] == "False":
                BlockPingAttacks = eval(y["BlockPingAttacks"])
            else:
                print("Invalid BlockPingAttacks in rule file. Defaulting to True")
                BlockPingAttacks = True
        else:
            print("BlockPingAttacks missing in rule file. Defaulting to True")
            BlockPingAttacks = True
        

    except FileNotFoundError:
        print("Rule file (firewallrules.json) not found, setting default values")
        ListOfBannedIpAddr = [] 
        ListOfBannedPorts = []
        ListOfBannedPrefixes = []
        TimeThreshold = 10  # sec
        PacketThreshold = 100    
        BlockPingAttacks = True

    def firewall(pkt):
        global DictOfPackets, AutoBlockedIPs

        sca = IP(pkt.get_payload())

        if sca.src in ListOfBannedIpAddr:
            print(sca.src, "is an incoming IP address that is already banned by the firewall.")
            pkt.drop()
            return

        if sca.haslayer(ICMP):  # Check if the packet is ICMP
            t = sca.getlayer(ICMP)
            if t.code == 0:
                print(f"Ping request received from {sca.src}")

                if sca.src in DictOfPackets:
                    temptime = list(DictOfPackets[sca.src])
                    if len(DictOfPackets[sca.src]) >= 20 and sca.src not in AutoBlockedIPs:
                        print(
                            f"Auto-blocking {sca.src} due to too many requests (auto-blocking after 20 requests)."
                        )
                        ListOfBannedIpAddr.append(sca.src)
                        AutoBlockedIPs.add(sca.src)
                        save_rules()
                        pkt.drop()
                        return

                    if len(DictOfPackets[sca.src]) == 10:
                        response = input(
                            f"Block {sca.src}? Enter 'y' to block, 'n' to continue: "
                        )
                        if response.lower() == "y":
                            print(f"Manually blocking {sca.src} as requested.")
                            ListOfBannedIpAddr.append(sca.src)
                            AutoBlockedIPs.add(sca.src)
                            save_rules()
                            pkt.drop()
                            return
                        elif response.lower() == "n":
                            print(f"Skipping blocking {sca.src} as requested.")
                            release_ip(sca.src)
                            DictOfPackets[sca.src].append(time.time())  # Continue tracking without blocking

                    DictOfPackets[sca.src].append(time.time())
                else:
                    DictOfPackets[sca.src] = [time.time()]

        if sca.haslayer(TCP):
            t = sca.getlayer(TCP)
            if t.dport in ListOfBannedPorts:
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()
                return

        if sca.haslayer(UDP):
            t = sca.getlayer(UDP)
            if t.dport in ListOfBannedPorts:
                print(t.dport, "is a destination port that is blocked by the firewall.")
                pkt.drop()
                return

        if True in [sca.src.find(suff) == 0 for suff in ListOfBannedPrefixes]:
            print("Prefix of " + sca.src + " is banned by the firewall.")
            pkt.drop()
            return

        if BlockPingAttacks and sca.haslayer(ICMP):  # attempt at preventing hping3
            t = sca.getlayer(ICMP)
            if t.code == 0:
                if sca.src in DictOfPackets:
                    temptime = list(DictOfPackets[sca.src])
                    if len(DictOfPackets[sca.src]) >= PacketThreshold:
                        if time.time() - DictOfPackets[sca.src][0] <= TimeThreshold:
                            print(
                                "Ping by %s blocked by the firewall (too many requests in a short span of time)."
                                % (sca.src)
                            )
                            ListOfBannedIpAddr.append(sca.src)
                            AutoBlockedIPs.add(sca.src)
                            save_rules()
                            pkt.drop()
                            return
                        else:
                            DictOfPackets[sca.src].pop(0)
                            DictOfPackets[sca.src].append(time.time())
                    else:
                        DictOfPackets[sca.src].append(time.time())
                else:
                    DictOfPackets[sca.src] = [time.time()]

                print(f"Ping request received from {sca.src}")
                pkt.accept()
                return

        pkt.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass

    nfqueue.unbind()

#if __name__ == "__main__":
 #   main()



# Main Function
def main():
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────██████████████─██████████─████████████████───██████████████─██████──────────██████─██████████████─██████─────────██████───────────────────────────────")
    print("────────────────────────────██░░░░░░░░░░██─██░░░░░░██─██░░░░░░░░░░░░██───██░░░░░░░░░░██─██░░██──────────██░░██─██░░░░░░░░░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██████████─████░░████─██░░████████░░██───██░░██████████─██░░██──────────██░░██─██░░██████░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██───────────██░░██───██░░██────██░░██───██░░██─────────██░░██──────────██░░██─██░░██──██░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██████████───██░░██───██░░████████░░██───██░░██████████─██░░██──██████──██░░██─██░░██████░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░░░░░░░░░██───██░░██───██░░░░░░░░░░░░██───██░░░░░░░░░░██─██░░██──██░░██──██░░██─██░░░░░░░░░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██████████───██░░██───██░░██████░░████───██░░██████████─██░░██──██░░██──██░░██─██░░██████░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██───────────██░░██───██░░██──██░░██─────██░░██─────────██░░██████░░██████░░██─██░░██──██░░██─██░░██─────────██░░██───────────────────────────────")
    print("────────────────────────────██░░██─────────████░░████─██░░██──██░░██████─██░░██████████─██░░░░░░░░░░░░░░░░░░██─██░░██──██░░██─██░░██████████─██░░██████████───────────────────────")
    print("────────────────────────────██░░██─────────██░░░░░░██─██░░██──██░░░░░░██─██░░░░░░░░░░██─██░░██████░░██████░░██─██░░██──██░░██─██░░░░░░░░░░██─██░░░░░░░░░░██───────────────────────")
    print("────────────────────────────██████─────────██████████─██████──██████████─██████████████─██████──██████──██████─██████──██████─██████████████─██████████████───────────────────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██████████████───████████──████████───────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░░░░░░░░░██───██░░░░██──██░░░░██───────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░██████░░██───████░░██──██░░████───────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░██──██░░██─────██░░░░██░░░░██─────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░██████░░████───████░░░░░░████─────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░░░░░░░░░░░██─────████░░████───────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░████████░░██───────██░░██─────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░██────██░░██───────██░░██─────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░████████░░██───────██░░██─────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────██░░░░░░░░░░░░██───────██░░██─────────────────────────────────────────────────────────────────────────────")
    print("────────────────────────────────────────────────────────────────────────████████████████───────██████─────────────────────────────────────────────────────────────────────────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("─████████████───██████████████─██████──██████─██████████████─██████████████─██████─────────██████████─██████████████─██████──────────██████─██████████████─██████████████─────────")
    print("─██░░░░░░░░████─██░░░░░░░░░░██─██░░██──██░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░██─────────██░░░░░░██─██░░░░░░░░░░██─██░░██████████──██░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─────────")
    print("─██░░████░░░░██─██░░██████████─██░░██──██░░██─██░░██████████─██░░██████░░██─██░░██─────────████░░████─██░░██████░░██─██░░░░░░░░░░██──██░░██─██████████░░██─██████████░░██─────────")
    print("─██░░██──██░░██─██░░██─────────██░░██──██░░██─██░░██─────────██░░██──██░░██─██░░██───────────██░░██───██░░██──██░░██─██░░██████░░██──██░░██─────────██░░██─────────██░░██─────────")
    print("─██░░██──██░░██─██░░██████████─██░░██──██░░██─██░░██─────────██░░██████░░██─██░░██───────────██░░██───██░░██──██░░██─██░░██──██░░██──██░░██─────────██░░██─────────██░░██─────────")
    print("─██░░██──██░░██─██░░░░░░░░░░██─██░░██──██░░██─██░░██─────────██░░░░░░░░░░██─██░░██───────────██░░██───██░░██──██░░██─██░░██──██░░██──██░░██─────────██░░██─────────██░░██─────────")
    print("─██░░██──██░░██─██░░██████████─██░░██──██░░██─██░░██─────────██░░██████░░██─██░░██───────────██░░██───██░░██──██░░██─██░░██──██░░██──██░░██─────────██░░██─────────██░░██─────────")
    print("─██░░██──██░░██─██░░██─────────██░░██──██░░██─██░░██─────────██░░██──██░░██─██░░██───────────██░░██───██░░██──██░░██─██░░██──██░░██████░░██─────────██░░██─────────██░░██─────────")
    print("─██░░████░░░░██─██░░██████████─██░░██████░░██─██░░██████████─██░░██──██░░██─██░░██████████─████░░████─██░░██████░░██─██░░██──██░░░░░░░░░░██─────────██░░██─────────██░░██─────────")
    print("─██░░░░░░░░████─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░██──██░░██─██░░░░░░░░░░██─██░░░░░░██─██░░░░░░░░░░██─██░░██──██████████░░██─────────██░░██─────────██░░██─────────")
    print("─████████████───██████████████─██████████████─██████████████─██████──██████─██████████████─██████████─██████████████─██████──────────██████─────────██████─────────██████─────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("Choose the Operation of the Firewall:")
    print("──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
    print("1. Live Packet Monitoring Operation")
    print("2. IPSec Operation")
    
    choice = input().strip()
    
    if choice == "1":
        monitor()
    elif choice == "2":
        IPSec()
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()


##This Code is build for the Network Programming Assingment and full owership is belongs to the A.K.N.Anupama