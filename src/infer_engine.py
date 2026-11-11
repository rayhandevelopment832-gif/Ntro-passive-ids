import json
import time
from pathlib import Path
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from src.ingest import PCAPIngestor
from src.feature_extractor import FlowFeatureExtractor

BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_PATH = BASE_DIR / "data" / "demo_traffic.pcap"
MODEL_PATH = BASE_DIR / "models" / "threat_classifier.pkl"
ALERT_PATH = BASE_DIR / "data" / "alerts.jsonl"

WINDOW_SECONDS = 5
SLIDE_SECONDS = 1

def get_severity(confidence, threat_class):
    if threat_class == "ddos" and confidence >= 0.75:
        return "High"
    if confidence >= 0.90:
        return "High"
    if confidence >= 0.70:
        return "Medium"
    return "Low"

def adapt_features(raw_features, feature_columns):
    """Map extracted window features into training dataset schema."""
    mapped = {}
    for col in feature_columns:
        if col == "duration":
            mapped[col] = raw_features.get("window_seconds", WINDOW_SECONDS)
        elif col == "packet_count":
            mapped[col] = raw_features.get("packet_count", 0)
        elif col == "byte_count":
            mapped[col] = raw_features.get("pkt_len_seq_mean", 0) * raw_features.get("packet_count", 0)
        elif col == "avg_packet_size":
            mapped[col] = raw_features.get("pkt_len_seq_mean", 0)
        elif col == "source_port":
            mapped[col] = 1024
        elif col == "destination_port":
            mapped[col] = 443
        elif col == "packet_interval":
            mapped[col] = raw_features.get("iat_mean", 0)
        elif col == "dns_entropy":
            mapped[col] = raw_features.get("dns_query_entropy", 0)
        elif col == "unique_destinations":
            mapped[col] = raw_features.get("fanout_dest_ips", 1)
        else:
            mapped[col] = raw_features.get(col, 0.0)
    return pd.DataFrame([mapped])

def main():
    print("\n========== STARTING REAL-TIME INFERENCE ENGINE ==========\n")
    if not PCAP_PATH.exists():
        raise FileNotFoundError(f"PCAP not found: {PCAP_PATH}")
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

    print("Loading trained classifier...")
    model_package = joblib.load(MODEL_PATH)
    model = model_package["model"]
    feature_columns = model_package["feature_columns"]

    ingestor = PCAPIngestor(PCAP_PATH)
    extractor = FlowFeatureExtractor()

    alerts = []
    latencies = []
    total_packets = 0
    window_count = 0

    start_time = time.time()

    print("Replaying PCAP stream and analyzing windows...")
    for w_start, w_end, window_packets in ingestor.stream_windows(WINDOW_SECONDS, SLIDE_SECONDS):
        t0 = time.time()
        window_count += 1
        total_packets += len(window_packets)

        raw_feats = extractor.extract_window_features(window_packets, WINDOW_SECONDS)
        if not raw_feats:
            continue

        raw_feats["window_seconds"] = WINDOW_SECONDS
        input_df = adapt_features(raw_feats, feature_columns)

        pred_class = model.predict(input_df)[0]
        probs = model.predict_proba(input_df)[0]
        confidence = float(np.max(probs))

        t1 = time.time()
        latencies.append((t1 - t0) * 1000.0)

        if pred_class != "benign":
            severity = get_severity(confidence, pred_class)
            src_ips = list({pkt[1].src for pkt in window_packets if pkt.haslayer("IP")})
            dst_ips = list({pkt[1].dst for pkt in window_packets if pkt.haslayer("IP")})

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "flow_id": f"flow_{window_count}",
                "window_start": w_start,
                "window_end": w_end,
                "src_ip": src_ips[0] if src_ips else "0.0.0.0",
                "dst_ip": dst_ips[0] if dst_ips else "0.0.0.0",
                "threat_class": str(pred_class),
                "confidence": round(confidence, 4),
                "severity": severity,
                "evidence": {
                    "packet_count": raw_feats.get("packet_count"),
                    "flow_rate_pps": round(raw_feats.get("flow_rate_pps", 0), 2),
                    "dns_entropy": round(raw_feats.get("dns_query_entropy", 0), 4)
                }
            }
            alerts.append(alert)

    total_time = time.time() - start_time
    fps = window_count / total_time if total_time > 0 else 0
    p95_latency = np.percentile(latencies, 95) if latencies else 0.0

    ALERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_PATH, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")

    print("\n========== INFERENCE COMPLETED ==========")
    print(f"Processed packets: {total_packets}")
    print(f"Processed feature windows: {window_count}")
    print(f"Generated alerts: {len(alerts)}")
    print(f"Total processing time: {total_time:.4f} seconds")
    print(f"Feature windows per second: {fps:.2f}")
    print(f"P95 inference latency: {p95_latency:.2f} ms")
    print(f"\nAlerts saved to: {ALERT_PATH}")

if __name__ == "__main__":
    main()