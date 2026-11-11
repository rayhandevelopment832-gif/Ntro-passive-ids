import argparse
import math
from collections import Counter
from pathlib import Path
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

class FlowFeatureExtractor:
    """
    Passive sliding-window network feature extractor.
    Supports 1s, 5s, and 30s windows.
    """
    def __init__(self, direction_resolver=None):
        self.direction_resolver = direction_resolver

    @staticmethod
    def calculate_entropy(values):
        """Calculate Shannon entropy."""
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def get_packet_info(packet):
        """Extract basic metadata from a packet."""
        info = {
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "packet_length": len(packet),
            "timestamp": float(packet.time),
            "dns_name": None,
            "dns_type": None,
            "tls_clienthello": False
        }
        if IP in packet:
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst
        if TCP in packet:
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                if (
                    len(payload) >= 6
                    and payload[0] == 0x16
                    and payload[1] == 0x03
                    and payload[2] in (0x01, 0x02, 0x03, 0x04)
                    and payload[5] == 0x01
                ):
                    info["tls_clienthello"] = True
        elif UDP in packet:
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport
            if DNS in packet and DNSQR in packet:
                try:
                    query = packet[DNSQR].qname
                    if isinstance(query, bytes):
                        query = query.decode("utf-8", errors="ignore")
                    info["dns_name"] = query.rstrip(".").lower()
                    info["dns_type"] = int(packet[DNSQR].qtype)
                except (ValueError, TypeError, AttributeError):
                    pass
        return info

    def extract_window_features(self, packets, window_seconds):
        """Extract features from one time window."""
        if not packets:
            return None
        infos = [self.get_packet_info(packet) for packet in packets]
        timestamps = sorted(info["timestamp"] for info in infos)
        packet_lengths = [info["packet_length"] for info in infos]
        total_packets = len(infos)
        total_bytes = sum(packet_lengths)
        source_ips = [info["src_ip"] for info in infos if info["src_ip"]]
        destination_ips = [info["dst_ip"] for info in infos if info["dst_ip"]]
        destination_ports = [info["dst_port"] for info in infos if info["dst_port"] is not None]

        iat_values = np.diff(timestamps)
        if len(iat_values) > 0:
            iat_mean = float(np.mean(iat_values))
            iat_std = float(np.std(iat_values))
        else:
            iat_mean = 0.0
            iat_std = 0.0

        dns_names = [info["dns_name"] for info in infos if info["dns_name"]]
        dns_entropy_values = [self.calculate_entropy(list(name)) for name in dns_names]
        dns_query_entropy = float(np.mean(dns_entropy_values)) if dns_entropy_values else 0.0
        dns_query_len = float(np.mean([len(name) for name in dns_names])) if dns_names else 0.0
        dns_types = [info["dns_type"] for info in infos if info["dns_type"] is not None]
        dns_record_type = Counter(dns_types).most_common(1)[0][0] if dns_types else 0

        tls_count = sum(info["tls_clienthello"] for info in infos)
        ja3_proxy_score = tls_count / total_packets

        outbound_bytes = 0
        inbound_bytes = 0
        direction_metadata_available = False

        if self.direction_resolver is not None:
            directions = [self.direction_resolver(packet) for packet in packets]
            valid_directions = {"outbound", "inbound"}
            if all(direction in valid_directions for direction in directions):
                direction_metadata_available = True
                for packet, direction in zip(packets, directions):
                    if direction == "outbound":
                        outbound_bytes += len(packet)
                    else:
                        inbound_bytes += len(packet)

        if direction_metadata_available and outbound_bytes > 0 and inbound_bytes > 0:
            outbound_inbound_ratio = outbound_bytes / inbound_bytes
            byte_asymmetry = abs(outbound_bytes - inbound_bytes) / (outbound_bytes + inbound_bytes)
        else:
            outbound_inbound_ratio = np.nan
            byte_asymmetry = np.nan

        features = {
            "packet_count": total_packets,
            "src_ip_entropy": self.calculate_entropy(source_ips),
            "flow_rate_pps": total_packets / window_seconds,
            "flow_rate_bps": total_bytes * 8 / window_seconds,
            "iat_mean": iat_mean,
            "iat_std_dev": iat_std,
            "dns_query_entropy": dns_query_entropy,
            "dns_query_len": dns_query_len,
            "dns_record_type": dns_record_type,
            "ja3_proxy_score": ja3_proxy_score,
            "pkt_len_seq_mean": float(np.mean(packet_lengths)),
            "pkt_len_seq_std": float(np.std(packet_lengths)),
            "fanout_dest_ports": len(set(destination_ports)),
            "fanout_dest_ips": len(set(destination_ips)),
            "outbound_inbound_ratio": outbound_inbound_ratio,
            "byte_asymmetry": byte_asymmetry
        }
        return features

    def extract(self, packets, window_seconds=5, slide_seconds=1):
        if window_seconds <= 0 or slide_seconds <= 0:
            raise ValueError("Window and slide durations must be positive.")
        packets = sorted(packets, key=lambda packet: float(packet.time))
        if not packets:
            return pd.DataFrame()
        packet_times = [float(packet.time) for packet in packets]
        first_time = packet_times[0]
        last_time = packet_times[-1]

        results = []
        window_start = first_time
        while window_start <= last_time:
            window_end = window_start + window_seconds
            window_packets = [
                packet for packet in packets
                if window_start <= float(packet.time) < window_end
            ]
            if window_packets:
                features = self.extract_window_features(window_packets, window_seconds)
                features["window_start"] = window_start
                features["window_end"] = window_end
                features["window_seconds"] = window_seconds
                results.append(features)
            window_start += slide_seconds
        return pd.DataFrame(results)

    def extract_pcap(self, pcap_path, window_seconds=5, slide_seconds=1):
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        print(f"Reading PCAP: {pcap_path}")
        packets = rdpcap(str(pcap_path))
        print(f"Total packets loaded: {len(packets)}")
        return self.extract(packets, window_seconds=window_seconds, slide_seconds=slide_seconds)

def main():
    parser = argparse.ArgumentParser(description="Passive Sliding-Window Feature Extractor")
    parser.add_argument("--pcap", default="data/demo_traffic.pcap", help="Input PCAP file")
    parser.add_argument("--window", type=float, choices=[1, 5, 30], default=5, help="Window duration in seconds")
    parser.add_argument("--slide", type=float, default=1, help="Sliding interval in seconds")
    args = parser.parse_args()

    if args.slide <= 0:
        parser.error("Slide duration must be positive.")

    extractor = FlowFeatureExtractor()
    input_path = Path(args.pcap)
    if not input_path.is_absolute():
        input_path = BASE_DIR / input_path

    print("\nStarting passive feature extraction...")
    features_df = extractor.extract_pcap(input_path, window_seconds=args.window, slide_seconds=args.slide)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    output_path = DATA_DIR / f"window_features_{int(args.window)}s.csv"
    features_df.to_csv(output_path, index=False)

    print("\nFeature extraction completed!")
    print(f"Windows extracted: {len(features_df)}")
    print(f"Output file: {output_path}")

    if not features_df.empty:
        print("\nExtracted features:")
        print(features_df.head())
        print("\nMissing values:")
        print(features_df.isna().sum())

if __name__ == "__main__":
    main()