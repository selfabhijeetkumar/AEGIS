"""AEGIS Demo Dataset — Realistic CICIDS 2017-style sample data for hackathon demo."""
import csv
import os
import random
from datetime import datetime, timedelta

DEMO_FILE = os.path.join(os.path.dirname(__file__), "data", "cicids_sample.csv")

ATTACK_IPS = [
    "185.220.101.42", "45.33.32.156", "103.75.190.11", "91.219.236.222",
    "209.141.55.26", "5.188.86.172", "218.92.0.107", "112.85.42.88",
    "77.247.181.163", "176.10.104.240", "198.98.56.12", "23.129.64.130",
    "171.25.193.78", "62.210.105.116", "89.234.157.254", "51.15.43.205",
    "193.218.118.183"
]

INTERNAL_IPS = ["10.0.0.1", "10.0.0.5", "10.0.0.12", "10.0.0.25", "10.0.0.100", "192.168.1.10", "192.168.1.50"]

ATTACK_LABELS = [
    ("SSH-Patator", 22, "TCP"),
    ("FTP-Patator", 21, "TCP"),
    ("DoS Hulk", 80, "TCP"),
    ("DoS Slowloris", 80, "TCP"),
    ("DoS GoldenEye", 80, "TCP"),
    ("PortScan", 0, "TCP"),  # Random ports
    ("Bot", 0, "TCP"),
    ("Web Attack – Brute Force", 80, "TCP"),
    ("Web Attack – XSS", 443, "TCP"),
    ("Infiltration", 0, "TCP"),
    ("Heartbleed", 443, "TCP"),
    ("DDoS", 80, "UDP"),
]


def generate_demo_dataset():
    """Generate a realistic demo CSV dataset with proper severity distribution."""
    os.makedirs(os.path.dirname(DEMO_FILE), exist_ok=True)

    rows = []
    base_time = datetime(2026, 4, 2, 2, 31, 0)

    # Generate 3000 rows: 85% benign, 15% attacks
    for i in range(3000):
        timestamp = base_time + timedelta(seconds=random.randint(0, 6600))  # ~2 hour window

        if random.random() < 0.85:
            # BENIGN traffic
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.140", "104.16.132.229"])
            dst_port = random.choice([80, 443, 53, 8080, 3306])
            protocol = random.choice(["TCP", "TCP", "TCP", "UDP"])
            fwd_packets = random.randint(1, 20)
            bwd_packets = random.randint(1, 15)
            flow_bytes = random.uniform(100, 50000)
            flow_duration = random.uniform(100, 500000)
            fwd_packets_per_s = random.uniform(1, 500)
            bwd_pkt_len_max = random.uniform(10, 400)
            label = "BENIGN"
        else:
            # ATTACK traffic
            attack = random.choice(ATTACK_LABELS)
            label = attack[0]
            dst_port = attack[1] if attack[1] > 0 else random.randint(1, 65535)
            protocol = attack[2]
            src_ip = random.choice(ATTACK_IPS)
            dst_ip = random.choice(INTERNAL_IPS)

            if "Patator" in label or "Brute" in label:
                fwd_packets = random.randint(50, 500)
                bwd_packets = random.randint(10, 50)
                flow_bytes = random.uniform(5000, 200000)
                flow_duration = random.uniform(1000, 50000)
                fwd_packets_per_s = random.uniform(2000, 9000)
                bwd_pkt_len_max = random.uniform(500, 1400)
            elif "DoS" in label or "DDoS" in label:
                fwd_packets = random.randint(100, 5000)
                bwd_packets = random.randint(0, 10)
                flow_bytes = random.uniform(100000, 5000000)
                flow_duration = random.uniform(100, 5000)
                fwd_packets_per_s = random.uniform(3000, 9000)
                bwd_pkt_len_max = random.uniform(600, 1400)
            elif "PortScan" in label:
                fwd_packets = random.randint(1, 5)
                bwd_packets = random.randint(0, 2)
                flow_bytes = random.uniform(50, 500)
                flow_duration = random.uniform(10, 100)
                dst_port = random.randint(1, 65535)
                fwd_packets_per_s = random.uniform(500, 3000)
                bwd_pkt_len_max = random.uniform(40, 200)
            elif "Infiltration" in label:
                fwd_packets = random.randint(10, 100)
                bwd_packets = random.randint(50, 500)
                flow_bytes = random.uniform(500000, 5000000)
                flow_duration = random.uniform(10000, 100000)
                fwd_packets_per_s = random.uniform(20000, 80000)
                bwd_pkt_len_max = random.uniform(3000, 10000)
            elif "Heartbleed" in label:
                fwd_packets = random.randint(5, 50)
                bwd_packets = random.randint(5, 50)
                flow_bytes = random.uniform(10000, 500000)
                flow_duration = random.uniform(1000, 20000)
                fwd_packets_per_s = random.uniform(25000, 60000)
                bwd_pkt_len_max = random.uniform(4000, 12000)
            elif "Bot" in label:
                fwd_packets = random.randint(5, 50)
                bwd_packets = random.randint(5, 50)
                flow_bytes = random.uniform(1000, 50000)
                flow_duration = random.uniform(5000, 50000)
                dst_port = random.choice([80, 443, 8443, 6667, 4444])
                fwd_packets_per_s = random.uniform(500, 5000)
                bwd_pkt_len_max = random.uniform(200, 1200)
            else:
                fwd_packets = random.randint(5, 100)
                bwd_packets = random.randint(5, 50)
                flow_bytes = random.uniform(1000, 100000)
                flow_duration = random.uniform(100, 10000)
                fwd_packets_per_s = random.uniform(500, 8000)
                bwd_pkt_len_max = random.uniform(100, 1400)

        rows.append({
            "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": src_ip,
            "Source Port": random.randint(1024, 65535),
            "Destination IP": dst_ip,
            "Destination Port": dst_port,
            "Protocol": 6 if protocol == "TCP" else 17,
            "Flow Duration": int(flow_duration),
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(flow_bytes * 0.6),
            "Total Length of Bwd Packets": int(flow_bytes * 0.4),
            "Flow Bytes/s": round(flow_bytes, 2),
            "Flow Packets/s": round((fwd_packets + bwd_packets) / max(flow_duration / 1000000, 0.001), 2),
            "Fwd Packets/s": round(fwd_packets_per_s, 2),
            "Bwd Packet Length Max": round(bwd_pkt_len_max, 2),
            "Fwd Packet Length Mean": round(flow_bytes * 0.6 / max(fwd_packets, 1), 2),
            "Bwd Packet Length Mean": round(flow_bytes * 0.4 / max(bwd_packets, 1), 2),
            "Flow IAT Mean": round(flow_duration / max(fwd_packets + bwd_packets, 1), 2),
            "Fwd IAT Mean": round(flow_duration / max(fwd_packets, 1), 2),
            "Bwd IAT Mean": round(flow_duration / max(bwd_packets, 1), 2),
            "Fwd PSH Flags": random.randint(0, 1),
            "SYN Flag Count": 1 if "Scan" in label or "Patator" in label else 0,
            "RST Flag Count": random.randint(0, 1),
            "ACK Flag Count": random.randint(0, 1),
            "Down/Up Ratio": round(bwd_packets / max(fwd_packets, 1), 2),
            "Avg Fwd Segment Size": round(flow_bytes * 0.6 / max(fwd_packets, 1), 2),
            "Avg Bwd Segment Size": round(flow_bytes * 0.4 / max(bwd_packets, 1), 2),
            "Subflow Fwd Bytes": int(flow_bytes * 0.6),
            "Subflow Bwd Bytes": int(flow_bytes * 0.4),
            "Init_Win_bytes_forward": random.choice([8192, 16384, 29200, 65535]),
            "Init_Win_bytes_backward": random.choice([8192, 16384, 29200, 65535]),
            "Label": label
        })

    # === FORCE INJECT GUARANTEED CRITICAL AND MEDIUM THREATS ===
    # Ensure at least 3 CRITICAL threats with extreme values
    critical_threats = [
        {
            "Timestamp": (base_time + timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "185.220.101.42",
            "Source Port": 4822,
            "Destination IP": "10.0.0.1",
            "Destination Port": 22,
            "Protocol": 6,
            "Flow Duration": 50000,
            "Total Fwd Packets": 5000,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": 5000000,
            "Total Length of Bwd Packets": 0,
            "Flow Bytes/s": 5000000.0,
            "Flow Packets/s": 100000.0,
            "Fwd Packets/s": 100000.0,
            "Bwd Packet Length Max": 8000.0,
            "Fwd Packet Length Mean": 1000.0,
            "Bwd Packet Length Mean": 0.0,
            "Flow IAT Mean": 10.0,
            "Fwd IAT Mean": 10.0,
            "Bwd IAT Mean": 0.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 0,
            "Down/Up Ratio": 0.0,
            "Avg Fwd Segment Size": 1000.0,
            "Avg Bwd Segment Size": 0.0,
            "Subflow Fwd Bytes": 5000000,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": 65535,
            "Init_Win_bytes_backward": 8192,
            "Label": "SSH-Patator"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=300)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "45.33.32.156",
            "Source Port": 8080,
            "Destination IP": "10.0.0.12",
            "Destination Port": 80,
            "Protocol": 6,
            "Flow Duration": 3000,
            "Total Fwd Packets": 10000,
            "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 5000000,
            "Total Length of Bwd Packets": 500,
            "Flow Bytes/s": 5000000.0,
            "Flow Packets/s": 100000.0,
            "Fwd Packets/s": 100000.0,
            "Bwd Packet Length Max": 7000.0,
            "Fwd Packet Length Mean": 500.0,
            "Bwd Packet Length Mean": 100.0,
            "Flow IAT Mean": 5.0,
            "Fwd IAT Mean": 5.0,
            "Bwd IAT Mean": 600.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.0005,
            "Avg Fwd Segment Size": 500.0,
            "Avg Bwd Segment Size": 100.0,
            "Subflow Fwd Bytes": 5000000,
            "Subflow Bwd Bytes": 500,
            "Init_Win_bytes_forward": 65535,
            "Init_Win_bytes_backward": 8192,
            "Label": "DoS Hulk"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=450)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "91.219.236.222",
            "Source Port": 6667,
            "Destination IP": "10.0.0.25",
            "Destination Port": 4444,
            "Protocol": 6,
            "Flow Duration": 80000,
            "Total Fwd Packets": 100,
            "Total Backward Packets": 500,
            "Total Length of Fwd Packets": 5000000,
            "Total Length of Bwd Packets": 3000000,
            "Flow Bytes/s": 100000.0,
            "Flow Packets/s": 7.5,
            "Fwd Packets/s": 1.25,
            "Bwd Packet Length Max": 10000.0,
            "Fwd Packet Length Mean": 50000.0,
            "Bwd Packet Length Mean": 6000.0,
            "Flow IAT Mean": 133333.0,
            "Fwd IAT Mean": 800000.0,
            "Bwd IAT Mean": 160.0,
            "Fwd PSH Flags": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 5.0,
            "Avg Fwd Segment Size": 50000.0,
            "Avg Bwd Segment Size": 6000.0,
            "Subflow Fwd Bytes": 5000000,
            "Subflow Bwd Bytes": 3000000,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 65535,
            "Label": "Infiltration"
        }
    ]

    # Add 5 MEDIUM threats with elevated but not extreme values
    medium_threats = [
        {
            "Timestamp": (base_time + timedelta(seconds=180)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "103.75.190.11",
            "Source Port": 4456,
            "Destination IP": "10.0.0.1",
            "Destination Port": 22,
            "Protocol": 6,
            "Flow Duration": 40000,
            "Total Fwd Packets": 200,
            "Total Backward Packets": 20,
            "Total Length of Fwd Packets": 80000,
            "Total Length of Bwd Packets": 2000,
            "Flow Bytes/s": 2000.0,
            "Flow Packets/s": 5.5,
            "Fwd Packets/s": 5.0,
            "Bwd Packet Length Max": 1200.0,
            "Fwd Packet Length Mean": 400.0,
            "Bwd Packet Length Mean": 100.0,
            "Flow IAT Mean": 181.0,
            "Fwd IAT Mean": 200.0,
            "Bwd IAT Mean": 2000.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.1,
            "Avg Fwd Segment Size": 400.0,
            "Avg Bwd Segment Size": 100.0,
            "Subflow Fwd Bytes": 80000,
            "Subflow Bwd Bytes": 2000,
            "Init_Win_bytes_forward": 16384,
            "Init_Win_bytes_backward": 8192,
            "Label": "SSH-Patator"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=360)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "218.92.0.107",
            "Source Port": 55123,
            "Destination IP": "10.0.0.1",
            "Destination Port": 80,
            "Protocol": 6,
            "Flow Duration": 4000,
            "Total Fwd Packets": 500,
            "Total Backward Packets": 3,
            "Total Length of Fwd Packets": 400000,
            "Total Length of Bwd Packets": 300,
            "Flow Bytes/s": 100000.0,
            "Flow Packets/s": 125.75,
            "Fwd Packets/s": 125.0,
            "Bwd Packet Length Max": 2000.0,
            "Fwd Packet Length Mean": 800.0,
            "Bwd Packet Length Mean": 100.0,
            "Flow IAT Mean": 7.95,
            "Fwd IAT Mean": 8.0,
            "Bwd IAT Mean": 1333.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.006,
            "Avg Fwd Segment Size": 800.0,
            "Avg Bwd Segment Size": 100.0,
            "Subflow Fwd Bytes": 400000,
            "Subflow Bwd Bytes": 300,
            "Init_Win_bytes_forward": 65535,
            "Init_Win_bytes_backward": 8192,
            "Label": "DoS Slowloris"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=520)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "5.188.86.172",
            "Source Port": 9001,
            "Destination IP": "10.0.0.25",
            "Destination Port": 3389,
            "Protocol": 6,
            "Flow Duration": 8000,
            "Total Fwd Packets": 150,
            "Total Backward Packets": 10,
            "Total Length of Fwd Packets": 120000,
            "Total Length of Bwd Packets": 1500,
            "Flow Bytes/s": 15000.0,
            "Flow Packets/s": 20.0,
            "Fwd Packets/s": 18.75,
            "Bwd Packet Length Max": 1800.0,
            "Fwd Packet Length Mean": 800.0,
            "Bwd Packet Length Mean": 150.0,
            "Flow IAT Mean": 50.0,
            "Fwd IAT Mean": 53.33,
            "Bwd IAT Mean": 800.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.067,
            "Avg Fwd Segment Size": 800.0,
            "Avg Bwd Segment Size": 150.0,
            "Subflow Fwd Bytes": 120000,
            "Subflow Bwd Bytes": 1500,
            "Init_Win_bytes_forward": 29200,
            "Init_Win_bytes_backward": 8192,
            "Label": "PortScan"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=600)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "112.85.42.88",
            "Source Port": 12345,
            "Destination IP": "10.0.0.5",
            "Destination Port": 443,
            "Protocol": 6,
            "Flow Duration": 6000,
            "Total Fwd Packets": 80,
            "Total Backward Packets": 40,
            "Total Length of Fwd Packets": 60000,
            "Total Length of Bwd Packets": 8000,
            "Flow Bytes/s": 11333.0,
            "Flow Packets/s": 20.0,
            "Fwd Packets/s": 13.33,
            "Bwd Packet Length Max": 1500.0,
            "Fwd Packet Length Mean": 750.0,
            "Bwd Packet Length Mean": 200.0,
            "Flow IAT Mean": 50.0,
            "Fwd IAT Mean": 75.0,
            "Bwd IAT Mean": 150.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 0,
            "RST Flag Count": 1,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.5,
            "Avg Fwd Segment Size": 750.0,
            "Avg Bwd Segment Size": 200.0,
            "Subflow Fwd Bytes": 60000,
            "Subflow Bwd Bytes": 8000,
            "Init_Win_bytes_forward": 16384,
            "Init_Win_bytes_backward": 16384,
            "Label": "Bot"
        },
        {
            "Timestamp": (base_time + timedelta(seconds=720)).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": "77.247.181.163",
            "Source Port": 54321,
            "Destination IP": "10.0.0.100",
            "Destination Port": 8080,
            "Protocol": 6,
            "Flow Duration": 5000,
            "Total Fwd Packets": 100,
            "Total Backward Packets": 8,
            "Total Length of Fwd Packets": 90000,
            "Total Length of Bwd Packets": 1200,
            "Flow Bytes/s": 18000.0,
            "Flow Packets/s": 21.6,
            "Fwd Packets/s": 20.0,
            "Bwd Packet Length Max": 1600.0,
            "Fwd Packet Length Mean": 900.0,
            "Bwd Packet Length Mean": 150.0,
            "Flow IAT Mean": 46.3,
            "Fwd IAT Mean": 50.0,
            "Bwd IAT Mean": 625.0,
            "Fwd PSH Flags": 1,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "ACK Flag Count": 1,
            "Down/Up Ratio": 0.08,
            "Avg Fwd Segment Size": 900.0,
            "Avg Bwd Segment Size": 150.0,
            "Subflow Fwd Bytes": 90000,
            "Subflow Bwd Bytes": 1200,
            "Init_Win_bytes_forward": 65535,
            "Init_Win_bytes_backward": 8192,
            "Label": "Web Attack – Brute Force"
        }
    ]

    # Inject forced threats
    rows.extend(critical_threats)
    rows.extend(medium_threats)

    # Sort by timestamp
    rows.sort(key=lambda x: x["Timestamp"])

    # Write CSV
    with open(DEMO_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    return DEMO_FILE


# Always regenerate on import to pick up new fields
generate_demo_dataset()
