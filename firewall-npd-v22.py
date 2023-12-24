from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import json

DictOfPackets = {}  # Initialize a dictionary to store packet information
AutoBlockedIPs = set()  # Keep track of IPs that have been auto-blocked

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
