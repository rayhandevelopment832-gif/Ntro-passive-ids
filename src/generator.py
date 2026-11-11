import argparse
import random
import string
import os
from pathlib import Path
import numpy as np
import pandas as pd
from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, Raw, Ether, wrpcap
)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

THREAT_CLASSES = [
    "benign",
    "ddos",
    "c2_beaconing",
    "dga",
    "encrypted_malware",
    "reconnaissance",
    "exfiltration"
]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_port():
    return random.choice([80, 443, 53, 8080, 22, 21, 25, 3389])

def random_domain(length=15):
    characters = string.ascii_lowercase + string.digits
    return "".join(random.choice(characters) for _ in range(length)) + ".com"

def generate_features(rows_per_class, benign_ratio=None):
    """
    Generates feature rows using continuous distributions with realistic overlap.
    If benign_ratio is None, produces a balanced dataset (rows_per_class per label).
    If benign_ratio is specified (e.g., 0.90), produces an imbalanced dataset (90% benign).
    """
    if benign_ratio is None:
        class_counts = {label: rows_per_class for label in THREAT_CLASSES}
    else:
        total_rows = rows_per_class * len(THREAT_CLASSES)
        benign_count = int(total_rows * benign_ratio)
        attack_classes = [c for c in THREAT_CLASSES if c != "benign"]
        attack_count_per_class = max(1, (total_rows - benign_count) // len(attack_classes))
        class_counts = {"benign": benign_count}
        for attack in attack_classes:
            class_counts[attack] = attack_count_per_class

    records = []
    for label, count in class_counts.items():
        for _ in range(count):
            source_port = random.randint(1024, 65535)

            if label == "benign":
                duration = max(0.01, float(np.random.exponential(scale=3.5)))
                packet_count = max(1, int(np.random.lognormal(mean=2.8, sigma=0.8)))
                byte_count = max(64, int(packet_count * np.random.normal(loc=650, scale=300)))
                destination_port = random.choice([80, 443, 53, 8080, 22, 445])
                packet_interval = max(0.001, float(np.random.exponential(scale=0.5)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.38, scale=0.18), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=1.8)))

            elif label == "ddos":
                duration = max(0.01, float(np.random.exponential(scale=1.5)))
                packet_count = max(10, int(np.random.normal(loc=2200, scale=750)))
                byte_count = max(500, int(packet_count * np.random.normal(loc=140, scale=50)))
                destination_port = random.choice([80, 443, 53, 8080])
                packet_interval = max(0.0001, float(np.random.exponential(scale=0.002)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.25, scale=0.1), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=2.5)))

            elif label == "c2_beaconing":
                packet_count = max(5, int(np.random.normal(loc=45, scale=15)))
                packet_interval = max(0.1, float(np.random.normal(loc=1.0, scale=0.15)))
                duration = packet_count * packet_interval
                byte_count = max(200, int(packet_count * np.random.normal(loc=280, scale=90)))
                destination_port = random.choice([443, 8080, 8443, 80])
                dns_entropy = float(np.clip(np.random.normal(loc=0.45, scale=0.15), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=1.2)))

            elif label == "dga":
                duration = max(0.01, float(np.random.exponential(scale=1.0)))
                packet_count = max(1, int(np.random.normal(loc=12, scale=5)))
                byte_count = max(64, int(packet_count * np.random.normal(loc=160, scale=60)))
                destination_port = random.choice([53, 53, 53, 8080])
                packet_interval = max(0.01, float(np.random.exponential(scale=0.2)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.72, scale=0.14), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=3.5)))

            elif label == "encrypted_malware":
                duration = max(0.1, float(np.random.exponential(scale=4.5)))
                packet_count = max(5, int(np.random.normal(loc=55, scale=20)))
                byte_count = max(500, int(packet_count * np.random.normal(loc=750, scale=220)))
                destination_port = random.choice([443, 8443, 443])
                packet_interval = max(0.01, float(np.random.exponential(scale=0.4)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.48, scale=0.15), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=2.0)))

            elif label == "reconnaissance":
                duration = max(0.05, float(np.random.exponential(scale=2.0)))
                packet_count = max(10, int(np.random.normal(loc=250, scale=80)))
                byte_count = max(200, int(packet_count * np.random.normal(loc=85, scale=30)))
                destination_port = random.randint(1, 65535)
                packet_interval = max(0.001, float(np.random.exponential(scale=0.01)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.22, scale=0.1), 0.0, 1.0))
                unique_destinations = max(4, int(np.random.normal(loc=35, scale=12)))

            elif label == "exfiltration":
                duration = max(1.0, float(np.random.exponential(scale=12.0)))
                byte_count = max(50000, int(np.random.lognormal(mean=12.8, sigma=0.75)))
                packet_count = max(10, int(byte_count / float(np.random.normal(loc=1350, scale=100))))
                destination_port = random.choice([443, 22, 21, 8080])
                packet_interval = max(0.001, float(np.random.exponential(scale=0.1)))
                dns_entropy = float(np.clip(np.random.normal(loc=0.42, scale=0.12), 0.0, 1.0))
                unique_destinations = max(1, int(np.random.poisson(lam=1.5)))

            avg_packet_size = byte_count / packet_count

            records.append({
                "duration": duration,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "avg_packet_size": avg_packet_size,
                "source_port": source_port,
                "destination_port": destination_port,
                "packet_interval": packet_interval,
                "dns_entropy": dns_entropy,
                "unique_destinations": unique_destinations,
                "label": label
            })

    df = pd.DataFrame(records)
    return df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

def make_packet(src, dst, sport, dport, size=200, protocol="TCP"):
    if protocol == "UDP":
        packet = (
            Ether() /
            IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport)
        )
    else:
        packet = (
            Ether() /
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, flags="PA")
        )
    payload_size = max(0, size - len(packet))
    packet = packet / Raw(load=os.urandom(payload_size))
    return packet

def generate_pcap(packets_per_class):
    packets = []
    base_time = 1700000000.0
    for label in THREAT_CLASSES:
        for i in range(packets_per_class):
            src = random_ip()
            dst = "192.0.2.10"
            sport = random.randint(1024, 65535)
            dport = 443
            size = 200
            protocol = "TCP"
            interval = max(0.001, float(np.random.exponential(scale=0.2)))

            if label == "benign":
                dport = random.choice([80, 443, 53, 8080])
                interval = max(0.01, float(np.random.exponential(scale=0.4)))
            elif label == "ddos":
                src = random_ip()
                interval = max(0.0001, float(np.random.exponential(scale=0.001)))
                size = max(60, int(np.random.normal(loc=250, scale=100)))
            elif label == "c2_beaconing":
                interval = max(0.1, float(np.random.normal(loc=1.0, scale=0.15)))
                size = max(50, int(np.random.normal(loc=120, scale=30)))
            elif label == "dga":
                dport = 53
                protocol = "UDP"
                interval = max(0.01, float(np.random.exponential(scale=0.15)))
            elif label == "encrypted_malware":
                dport = random.choice([443, 8443])
                size = max(200, int(np.random.normal(loc=850, scale=300)))
                protocol = "TCP"
            elif label == "reconnaissance":
                dport = random.randint(1, 65535)
                interval = max(0.0005, float(np.random.exponential(scale=0.005)))
            elif label == "exfiltration":
                dport = random.choice([443, 22, 21])
                size = max(500, int(np.random.normal(loc=1350, scale=100)))

            if label == "dga":
                domain = random_domain()
                packet = (
                    Ether() /
                    IP(src=src, dst=dst) /
                    UDP(sport=sport, dport=53) /
                    DNS(
                        rd=1,
                        qd=DNSQR(qname=domain)
                    )
                )
            else:
                packet = make_packet(
                    src, dst, sport, dport, size, protocol
                )

            if label == "encrypted_malware":
                packet = packet / Raw(
                    load=b"\x16\x03\x01\x00\x2f"
                )

            packet.time = base_time
            base_time += interval
            packets.append(packet)

    packets.sort(key=lambda packet: packet.time)
    return packets

def main():
    parser = argparse.ArgumentParser(
        description="Synthetic Network Traffic Generator"
    )
    parser.add_argument(
        "--rows-per-class",
        type=int,
        default=500
    )
    parser.add_argument(
        "--packets-per-class",
        type=int,
        default=100
    )
    args = parser.parse_args()

    if args.rows_per_class < 1 or args.packets_per_class < 1:
        parser.error("Both counts must be at least 1.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Generate BALANCED training dataset (3,500 total rows: 500 per class)
    print("Generating BALANCED training dataset...")
    df_train = generate_features(args.rows_per_class, benign_ratio=None)
    train_csv_path = DATA_DIR / "train_features.csv"
    df_train.to_csv(train_csv_path, index=False)

    # 2. Generate IMBALANCED evaluation test dataset (3,500 total rows: 90% Benign / 10% Attacks)
    print("Generating IMBALANCED evaluation test dataset (90% Benign / 10% Attacks)...")
    df_test = generate_features(args.rows_per_class, benign_ratio=0.90)
    test_csv_path = DATA_DIR / "test_features.csv"
    df_test.to_csv(test_csv_path, index=False)

    # 3. Generate PCAP file
    print("Generating synthetic PCAP traffic...")
    packets = generate_pcap(args.packets_per_class)
    pcap_path = DATA_DIR / "demo_traffic.pcap"
    wrpcap(str(pcap_path), packets)

    print("\nGeneration completed successfully!")
    print(f"Train Dataset: {train_csv_path} ({len(df_train)} rows)")
    print(f"Test Dataset:  {test_csv_path} ({len(df_test)} rows)")
    print(f"PCAP:          {pcap_path}")
    print("\nTrain Class Distribution:")
    print(df_train["label"].value_counts())
    print("\nTest Class Distribution:")
    print(df_test["label"].value_counts())

if __name__ == "__main__":
    main()