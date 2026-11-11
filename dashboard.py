import json
import time
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
import streamlit as st

from src.ingest import PCAPIngestor
from src.feature_extractor import FlowFeatureExtractor
from src.infer_engine import adapt_features, get_severity

# PROJECT PATHS
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "threat_classifier.pkl"
DEFAULT_PCAP = BASE_DIR / "data" / "demo_traffic.pcap"
ALERT_PATH = BASE_DIR / "data" / "alerts.jsonl"

# PAGE CONFIGURATION
st.set_page_config(
    page_title="NTRO Passive AI IDS",
    page_icon="🛡️",
    layout="wide"
)

# CUSTOM DASHBOARD STYLING
st.markdown("""
<style>
.main {
    background-color: #0b1120;
}
.block-container {
    padding-top: 1.5rem;
}
.metric-card {
    background-color: #172337;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #293b55;
}
.metric-title {
    color: #9caec5;
    font-size: 14px;
}
.metric-value {
    color: #ffffff;
    font-size: 27px;
    font-weight: bold;
}
.dashboard-subtitle {
    color: #9caec5;
    font-size: 14px;
}
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None
    package = joblib.load(MODEL_PATH)
    return package

# HEADER
st.title("🛡️ NTRO PASSIVE AI IDS")
st.markdown(
    '<p class="dashboard-subtitle">'
    'AI-Based Detection of Cyber Threats in Unidirectional IP Traffic'
    '</p>',
    unsafe_allow_html=True
)
st.divider()

# SIDEBAR CONFIGURATION
st.sidebar.title("⚙️ Detection Configuration")
pcap_input = st.sidebar.text_input(
    "PCAP File Path",
    value=str(DEFAULT_PCAP)
)
window_seconds = st.sidebar.selectbox(
    "Feature Window",
    options=[1, 5, 30],
    index=1
)
slide_seconds = st.sidebar.number_input(
    "Slide Interval (seconds)",
    min_value=1,
    max_value=window_seconds,
    value=1
)
confidence_threshold = st.sidebar.slider(
    "Confidence Threshold",
    min_value=0.50,
    max_value=1.00,
    value=0.70,
    step=0.05
)
st.sidebar.markdown("---")
st.sidebar.info(
    "Passive monitoring mode:\n\n"
    "- Read-only PCAP replay\n"
    "- No active probing\n"
    "- No packet transmission\n"
    "- No inline blocking\n"
    "- No payload decryption"
)

def run_detection(pcap_path, window_seconds, slide_seconds, confidence_threshold, model_package):
    model = model_package["model"]
    feature_columns = model_package["feature_columns"]

    ingestor = PCAPIngestor(pcap_path)
    extractor = FlowFeatureExtractor()

    alerts = []
    prediction_counts = Counter()
    latest_features = {}
    processed_windows = 0
    processed_packets = 0
    seen_packet_ids = set()
    latency_values = []
    start_time = time.perf_counter()

    for window_start, window_end, packets in ingestor.stream_windows(
        window_seconds=window_seconds,
        slide_seconds=slide_seconds
    ):
        window_start_time = time.perf_counter()
        processed_windows += 1

        for packet in packets:
            packet_id = id(packet)
            if packet_id not in seen_packet_ids:
                seen_packet_ids.add(packet_id)
                processed_packets += 1

        features = extractor.extract_window_features(packets, window_seconds)
        if features is None:
            continue
        features["window_seconds"] = window_seconds
        latest_features = features

        model_input = adapt_features(features, feature_columns)
        prediction = model.predict(model_input)[0]
        probabilities = model.predict_proba(model_input)[0]
        confidence = float(np.max(probabilities))
        prediction_counts[str(prediction)] += 1

        if prediction != "benign" and confidence >= confidence_threshold:
            severity = get_severity(confidence, prediction)
            src_ips = list({pkt[1].src for pkt in packets if pkt.haslayer("IP")})
            dst_ips = list({pkt[1].dst for pkt in packets if pkt.haslayer("IP")})

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "flow_id": f"flow_{processed_windows}",
                "window_start": window_start,
                "window_end": window_end,
                "src_ip": src_ips[0] if src_ips else "0.0.0.0",
                "dst_ip": dst_ips[0] if dst_ips else "0.0.0.0",
                "threat_class": str(prediction),
                "confidence": round(confidence, 4),
                "severity": severity,
                "supporting_evidence": {
                    "severity": severity,
                    "packet_count": features.get("packet_count"),
                    "flow_rate_pps": round(features.get("flow_rate_pps", 0), 2),
                    "dns_entropy": round(features.get("dns_query_entropy", 0), 4)
                }
            }
            alerts.append(alert)

        latency = (time.perf_counter() - window_start_time) * 1000
        latency_values.append(latency)

    total_time = time.perf_counter() - start_time
    throughput = processed_windows / total_time if total_time > 0 else 0
    p95_latency = float(np.percentile(latency_values, 95)) if latency_values else 0.0

    ALERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_PATH, "w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert) + "\n")

    return {
        "packets": processed_packets,
        "windows": processed_windows,
        "alerts": alerts,
        "prediction_counts": prediction_counts,
        "features": latest_features,
        "throughput": throughput,
        "p95_latency": p95_latency,
        "total_time": total_time
    }

# START REPLAY INTERFACE
if st.sidebar.button("▶ Start PCAP Replay", type="primary", use_container_width=True):
    model_package = load_model()
    if model_package is None:
        st.error("Model not found. Run python -m src.train first.")
    elif not Path(pcap_input).is_file():
        st.error("PCAP file not found. Check the file path.")
    else:
        try:
            with st.spinner("Reading packets and running AI inference..."):
                results = run_detection(
                    pcap_input,
                    window_seconds,
                    slide_seconds,
                    confidence_threshold,
                    model_package
                )
                st.session_state["results"] = results
            st.success("PCAP replay completed successfully!")
        except Exception as error:
            st.error(f"Detection error: {error}")

# RESULTS DISPLAY
if "results" not in st.session_state:
    st.info("Configure your PCAP and detection settings in the sidebar, then click Start PCAP Replay.")
else:
    results = st.session_state["results"]
    alerts = results["alerts"]
    features = results["features"]

    # TOP METRICS BAR
    st.subheader("📊 System Performance")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Packets Processed", f"{results['packets']:,}")
    with col2:
        st.metric("Threat Alerts", f"{len(alerts):,}")
    with col3:
        st.metric("Windows / Sec", f"{results['throughput']:.2f}")
    with col4:
        st.metric("P95 Latency", f"{results['p95_latency']:.2f} ms")
    st.caption(
        f"Feature windows processed: {results['windows']} | "
        f"Total replay time: {results['total_time']:.3f} seconds"
    )
    st.divider()

    # LIVE THREAT FEED
    st.subheader("🚨 Threat Detection Feed")
    if alerts:
        alert_rows = []
        for alert in reversed(alerts):
            evidence = alert["supporting_evidence"]
            alert_rows.append({
                "Timestamp": alert["timestamp"],
                "Threat": alert["threat_class"],
                "Source IP": alert["src_ip"],
                "Destination IP": alert["dst_ip"],
                "Confidence": alert["confidence"],
                "Severity": evidence["severity"]
            })
        st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)

        selected_alert_index = st.selectbox(
            "Select alert to inspect",
            options=range(len(alerts)),
            format_func=lambda i: (
                f"{alerts[i]['threat_class']} | "
                f"{alerts[i]['src_ip']} | "
                f"{alerts[i]['confidence']:.2%}"
            )
        )
        selected_alert = alerts[selected_alert_index]
        sev = selected_alert["supporting_evidence"]["severity"]
        if sev == "High":
            st.error(f"High severity: {selected_alert['threat_class']}")
        elif sev == "Medium":
            st.warning(f"Medium severity: {selected_alert['threat_class']}")
        else:
            st.info(f"Low severity: {selected_alert['threat_class']}")
    else:
        st.success("No threats crossed the selected confidence threshold.")
    st.divider()

    # FEATURE EVIDENCE INSPECTOR
    st.subheader("🔍 Feature Evidence Inspector")
    if features:
        evidence_col1, evidence_col2 = st.columns(2)
        with evidence_col1:
            st.metric("DNS Entropy", f"{features.get('dns_query_entropy', 0.0):.4f}")
            st.metric("DNS Query Length", f"{features.get('dns_query_len', 0.0):.2f}")
            st.metric("Destination Ports", features.get("fanout_dest_ports", 0))
        with evidence_col2:
            st.metric("IAT Standard Deviation", f"{features.get('iat_std_dev', 0.0):.6f}")
            st.metric("Packets per Second", f"{features.get('flow_rate_pps', 0.0):.2f}")
            st.metric("Average Packet Size", f"{features.get('pkt_len_seq_mean', 0.0):.2f} bytes")
    else:
        st.info("No feature windows were available.")
    st.divider()

    # THREAT DISTRIBUTION
    st.subheader("📈 Threat Distribution")
    distribution = results["prediction_counts"]
    threat_distribution = {
        label: count
        for label, count in distribution.items()
        if label != "benign"
    }
    if threat_distribution:
        chart_df = pd.DataFrame(
            list(threat_distribution.items()),
            columns=["Threat Category", "Windows"]
        )
        st.bar_chart(chart_df.set_index("Threat Category"), use_container_width=True)
    else:
        st.info("No non-benign predictions in this replay.")
    st.caption("Distribution counts predicted feature windows, not unique network flows.")
    st.divider()

    # DOWNLOAD ALERTS
    st.subheader("📁 Export Detection Results")
    alert_jsonl = "\n".join(json.dumps(alert) for alert in alerts)
    if alert_jsonl:
        st.download_button(
            label="⬇ Download Alerts (JSONL)",
            data=alert_jsonl + "\n",
            file_name="alerts.jsonl",
            mime="application/x-ndjson"
        )
    else:
        st.caption("No alerts available for export.")

# FOOTER
st.divider()
st.markdown(
    """
    <div style="text-align:center; color:#8292a8;">
    NTRO Passive AI IDS | Read-Only Network Monitoring<br>
    Synthetic Prototype | No Active Network Intervention
    </div>
    """,
    unsafe_allow_html=True
)