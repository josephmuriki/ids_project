from collections import defaultdict
from datetime import datetime

flows = defaultdict(list)

def create_flow_key(packet):

    try:

        if packet.haslayer("IP"):

            src = packet["IP"].src
            dst = packet["IP"].dst
            proto = packet["IP"].proto

            sport = 0
            dport = 0

            if packet.haslayer("TCP"):
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport

            elif packet.haslayer("UDP"):
                sport = packet["UDP"].sport
                dport = packet["UDP"].dport

            return (
                src,
                dst,
                sport,
                dport,
                proto
            )

    except Exception as e:
        print("Flow Key Error:", e)

    return None

def add_packet_to_flow(packet):

    key = create_flow_key(packet)
    reverse_key = None

    if key is None:
        return None

    packet_info = {
        "time": datetime.now(),
        "length": len(packet),
        "direction": "forward",

        "syn": 0,
        "ack": 0,
        "psh": 0,
        "urg": 0,

        "protocol": "OTHER"

    }

    if packet.haslayer("TCP"):

        packet_info["protocol"] = "TCP"

        flags = packet["TCP"].flags

        if flags & 0x02:
            packet_info["syn"] = 1

        if flags & 0x10:
            packet_info["ack"] = 1

        if flags & 0x08:
            packet_info["psh"] = 1

        if flags & 0x20:
            packet_info["urg"] = 1
    elif packet.haslayer("UDP"):
        packet_info["protocol"] = "UDP"

    flows[key].append(packet_info)

    return key

def extract_flow_features(flow_packets):

    try:

        packet_count = len(flow_packets)

        total_bytes = sum(
            p["length"]
            for p in flow_packets
        )

        avg_packet_size = total_bytes / packet_count

        duration = (
            flow_packets[-1]["time"] -
            flow_packets[0]["time"]
        ).total_seconds()

        return {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_packet_size,
            "duration": duration
        }

    except Exception as e:
        print("Feature Extraction Error:", e)

        return None