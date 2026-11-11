AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
A passive, machine-learning-assisted intrusion detection prototype for analysing one-directional network traffic from PCAP files. The system extracts statistical traffic features, classifies observed traffic into threat categories, emits structured JSON alerts, and presents replay results through a Streamlit dashboard.
Project Overview
The prototype follows a passive-monitoring model:
- Reads packets from PCAP files and replays them for analysis.
- Does not transmit packets, perform active probing, or block traffic.
- Does not decrypt application payloads.
- Uses packet headers, timing, lengths, DNS metadata, and other observable traffic characteristics.
- Produces machine-readable JSON Lines alerts.
- Provides a dashboard for reviewing threat classifications and supporting evidence.
The six threat categories covered by the demonstration are:
1. Volumetric/protocol DDoS
2. Botnet command-and-control (C2) beaconing
3. DGA and DNS tunnelling
4. Encrypted malware metadata patterns
5. Reconnaissance and port scanning
6. Data exfiltration
Benign traffic is included as a seventh class for model training.
Prototype status: This is a hackathon/research prototype. Synthetic training data demonstrates the end-to-end workflow; it does not establish real-world detection accuracy. Validate against representative, independently labelled traffic before making operational claims.

Architecture
PCAP file / synthetic PCAP
          |
          v
   Read-only PCAP replay
          |
          v
  Sliding-window feature extraction
          |
          v
  Trained Random Forest classifier
          |
          v
   JSONL alert generation
          |
          v
  Streamlit monitoring dashboard
Repository Structure
ntro_passive_ids/
├── data/
│   ├── train_features.csv       # Generated labelled feature dataset
│   ├── demo_traffic.pcap        # Generated synthetic PCAP
│   └── alerts.jsonl             # Generated inference alerts
├── models/
│   └── threat_classifier.pkl    # Trained model bundle
├── src/
│   ├── __init__.py
│   ├── generator.py             # Synthetic data and PCAP generator
│   ├── ingest.py                # Read-only PCAP replay
│   ├── feature_extractor.py     # Sliding-window feature extraction
│   ├── train.py                 # Model training and evaluation
│   └── infer_engine.py          # Streaming inference and alert creation
├── dashboard.py                 # Streamlit dashboard
├── requirements.txt
└── README.md
Technology Stack
- Python 3.11 — application runtime
- Scapy — PCAP reading and synthetic packet generation
- Pandas and NumPy — dataset and numerical processing
- Scikit-learn — preprocessing, Random Forest classification, and evaluation
- Joblib — model serialization
- Streamlit — monitoring dashboard
- Plotly — threat distribution visualization
Requirements
- Windows, Linux, or macOS
- Python 3.11 recommended
- Internet access for installing Python dependencies
- No GPU required for this prototype
- Sufficient memory and disk space for the PCAP and generated dataset
Installation
Windows PowerShell
Open PowerShell in the project directory:
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
If PowerShell prevents activation, use the following command for the current terminal session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
Linux / macOS
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
Running the Project
Run each stage from the project root directory, with the virtual environment activated.
Step 1 — Generate the synthetic dataset and PCAP
python -m src.generator --rows-per-class 500 --packets-per-class 100
This creates data/train_features.csv and data/demo_traffic.pcap.

The CSV contains synthetic labelled feature rows for benign traffic and all six threat categories. The PCAP contains synthetic packets for offline replay.
Step 2 — Feature extraction
Feature extraction is implemented in src/feature_extractor.py and is invoked by the inference engine during PCAP replay.

The FlowFeatureExtractor class aggregates packets into configurable time windows. The default inference window is five seconds; one-, five-, and thirty-second window sizes can be selected in the dashboard.
Step 3 — Train and evaluate the classifier
python -m src.train
The training pipeline:
1. Loads the generated feature CSV.
2. Separates features and class labels.
3. Splits data into training and test sets using stratification.
4. Applies median imputation and feature scaling.
5. Trains a Random Forest multiclass classifier.
6. Prints accuracy, a classification report, a confusion matrix, and permutation feature importance.
7. Saves the model bundle to models/threat_classifier.pkl.
Step 4 — Run PCAP replay and inference
python -m src.infer_engine
Optional arguments:
python -m src.infer_engine --pcap data/demo_traffic.pcap --model models/threat_classifier.pkl --window 5 --speed 0 --threshold 0.60 --alerts data/alerts.jsonl
- --pcap: input PCAP path
- --model: trained model path
- --window: feature-window duration in seconds
- --speed: replay speed; 0 means as fast as possible and 1 approximates capture-time replay
- --threshold: minimum model confidence for generating a threat alert
- --alerts: JSON Lines output path
Alerts are written to data/alerts.jsonl, one JSON object per line.
Step 5 — Launch the dashboard
streamlit run dashboard.py
Use the sidebar to select a PCAP file, feature window, confidence threshold, and replay speed. Select Run PCAP replay to process the file and display the results.
Extracted Features
Feature	Description
src_ip_entropy	Shannon entropy of source IP addresses observed in the window
flow_rate_pps	Observed packet count divided by the configured window duration
flow_rate_bps	Observed packet bytes converted to bits per second
iat_mean	Mean inter-arrival time between observed packets
iat_std_dev	Population standard deviation of inter-arrival times
dns_query_entropy	Character entropy of the most recently observed DNS query name
dns_query_len	Length of the observed DNS query name
dns_record_type	DNS query record type
ja3_proxy_score	Simplified TLS ClientHello-shaped metadata indicator
pkt_len_seq_mean	Mean packet length in the window
pkt_len_seq_std	Standard deviation of packet lengths
fanout_dest_ports	Maximum number of unique destination ports observed for one source IP
fanout_dest_ips	Maximum number of unique destination IPs observed for one source IP
outbound_inbound_ratio	Outbound/inbound byte ratio when trusted direction metadata is available
byte_asymmetry	Directional byte asymmetry when trusted direction metadata is available


Alert Format
Each alert follows this JSON structure:
{
  "timestamp": "2026-11-11T12:00:00+00:00",
  "flow_id": "192.0.2.10:198.51.100.10:tcp:1700000000000",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.10",
  "threat_class": "recon_scan",
  "confidence": 0.91,
  "supporting_evidence": {
    "fanout_dest_ports": 80,
    "flow_rate_pps": 42.5,
    "severity": "Medium"
  }
}
The example values are illustrative. Actual values depend on the input PCAP and model prediction.
Dashboard Components
The Streamlit dashboard provides:
- Traffic metrics: packets processed, generated alerts, processing throughput, and P95 inference latency.
- Threat feed: detected threat class, confidence, source and destination IP addresses, timestamp, and severity.
- Evidence inspector: feature values associated with the selected alert.
- Threat breakdown: distribution of generated alerts by predicted threat class.
The current dashboard processes a selected PCAP when the replay button is clicked. It is an offline replay dashboard, not a continuous live network-capture service.
Important Technical Limitations
Synthetic data and model validity
The generated training data uses class-specific statistical patterns. High test scores on this dataset measure how well the model learns those generated patterns; they do not prove performance on real network traffic.

For meaningful validation, use authorized and independently labelled PCAP datasets. Keep training and test captures separate to avoid data leakage.
One-directional traffic visibility
A strictly one-directional sensor cannot observe the opposite direction unless that information is provided by a trusted source. Therefore, outbound_inbound_ratio and byte_asymmetry are unavailable by default and are represented as null when direction metadata is absent.
TLS fingerprinting
The current ja3_proxy_score is a simplified indicator based on TLS-record-shaped packet metadata. It is not a standards-compliant JA3 or JA4 fingerprint implementation. A production implementation must parse the relevant ClientHello fields and follow the applicable fingerprint specification.
Flow and window terminology
The current implementation aggregates packets into time windows. Its throughput measurement is feature windows processed per second, not true bidirectional network flows per second. A flow-oriented benchmark requires a flow table, flow keys, lifecycle handling, and explicit flow counting.
Streaming and latency
The current implementation supports offline PCAP replay and bounded time-window aggregation. It is not a production packet-capture deployment. Production use would require additional engineering for queue backpressure, packet-loss accounting, memory limits, clock handling, alert deduplication, and end-to-end latency measurement.
Severity labels
Severity labels are presentation mappings for the demonstration. They are not a calibrated risk score and should be adapted to the operational environment.
Security and Responsible Use
- Analyse only PCAP files that you own or are authorized to inspect.
- Keep the sensor passive and read-only.
- Do not use this prototype to transmit packets, probe systems, or disrupt network services.
- Do not attempt to decrypt protected application traffic.
- Treat alerts as investigative leads, not definitive proof of compromise.
- Protect PCAP files and alert logs because they may contain sensitive network metadata.
Suggested Validation and Future Work
1. Validate with representative, labelled PCAP datasets.
2. Add a proper bidirectional flow table where the sensor architecture permits it.
3. Implement standards-compliant JA3/JA4 extraction from visible handshake metadata.
4. Improve beacon detection using per-host periodicity and jitter analysis.
5. Add robust DNS tunnelling and DGA analysis at the domain level.
6. Introduce streaming queues with explicit backpressure and packet-drop counters.
7. Add alert schema validation, deduplication, and configurable severity policies.
8. Benchmark sustained throughput and end-to-end P50/P95/P99 latency on documented hardware.
9. Track false-positive and false-negative rates for each threat class.
License
Add the license applicable to your project before public distribution. If no license is specified, all rights remain with the copyright holder.