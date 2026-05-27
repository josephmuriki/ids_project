import numpy as np

def extract_features(flow_packets):

    try:

        packet_lengths = [
            p["length"]
            for p in flow_packets
        ]

        timestamps = [
            p["time"]
            for p in flow_packets
        ]

        total_packets = len(packet_lengths)

        total_bytes = sum(packet_lengths)

        duration = (
            timestamps[-1] - timestamps[0]
        ).total_seconds()

        if duration <= 0:
            duration = 1

        avg_packet_size = np.mean(packet_lengths)

        std_packet_size = np.std(packet_lengths)

        max_packet_size = np.max(packet_lengths)

        min_packet_size = np.min(packet_lengths)

        packets_per_second = (
            total_packets / duration
        )

        bytes_per_second = (
            total_bytes / duration
        )

        syn_count = sum(
            p["syn"]
            for p in flow_packets
        )

        ack_count = sum(
            p["ack"]
            for p in flow_packets
        )

        psh_count = sum(
            p["psh"]
            for p in flow_packets
        )

        urg_count = sum(
            p["urg"]
            for p in flow_packets
        )

        inter_arrival_times = []

        for i in range(1, len(timestamps)):

            delta = (
                timestamps[i] -
                timestamps[i - 1]
            ).total_seconds()

            inter_arrival_times.append(delta)

        flow_iat_mean = (
            np.mean(inter_arrival_times)
            if inter_arrival_times else 0
        )

        flow_iat_std = (
            np.std(inter_arrival_times)
            if inter_arrival_times else 0
        )

        feature_vector = [

            duration,
            total_packets,
            total_bytes,
            avg_packet_size,
            std_packet_size,
            max_packet_size,
            min_packet_size,

            packets_per_second,
            bytes_per_second,

            syn_count,
            ack_count,
            psh_count,
            urg_count,

            flow_iat_mean,
            flow_iat_std

        ]

        return feature_vector

    except Exception as e:

        print("Feature Extraction Error:", e)

        return None