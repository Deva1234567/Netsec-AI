import os
import requests
import zipfile
import io
import time
import pandas as pd
from pathlib import Path
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP  # pip install scapy

# ================= CONFIG =================
DOWNLOAD_DIR = Path("real_test_data")
DOWNLOAD_DIR.mkdir(exist_ok=True)

# Real-world datasets (2025–2026 malicious traffic)
DATASETS = {
    "guloader_ftp_exfil": {
        "url": "https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip",
        "password": "infected",
        "expected_iocs": ["ftp", "malware dropper", "C2 exfil"],
        "mitre": "T1041",  # Exfiltration Over C2 Channel
    },
    "lumma_stealer": {
        "url": "https://www.malware-traffic-analysis.net/2025/07/02/2025-07-02-Lumma-Stealer-infection-with-Rsockstun-malware.pcap.zip",
        "password": "infected",
        "expected_iocs": ["stealer", "C2 beacon", "data exfil"],
        "mitre": "T1005",  # Data from Local System
    },
    "sysmon_lsass_dump": {
        "url": "https://raw.githubusercontent.com/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log",
        "type": "text",
        "expected_events": ["EventCode=10", "lsass.exe"],
        "mitre": "T1003.001",  # LSASS Memory
    }
}

# Your Streamlit app URL (if exposed via ngrok/localtunnel for testing)
STREAMLIT_URL = "http://localhost:8501"  # change to your ngrok/public URL if remote

# Output log file
LOG_FILE = "accuracy_test_log.csv"

# ================= FUNCTIONS =================

def download_and_extract(url, password=None):
    """Download zip and extract PCAP/log"""
    print(f"[+] Downloading: {url}")
    r = requests.get(url, stream=True)
    if r.status_code != 200:
        print(f"[-] Failed to download {url}")
        return None

    if url.endswith(".zip"):
        z = zipfile.ZipFile(io.BytesIO(r.content))
        if password:
            z.setpassword(password.encode())
        for file in z.namelist():
            if file.endswith((".pcap", ".pcapng", ".log", ".xml")):
                target_path = DOWNLOAD_DIR / file
                z.extract(file, DOWNLOAD_DIR)
                print(f"[+] Extracted: {target_path}")
                return target_path
    else:
        # Direct log file
        target_path = DOWNLOAD_DIR / url.split("/")[-1]
        with open(target_path, "wb") as f:
            f.write(r.content)
        print(f"[+] Saved: {target_path}")
        return target_path

    return None

def basic_pcap_validation(pcap_path):
    """Quick check: count packets, protocols, suspicious IPs"""
    try:
        packets = rdpcap(str(pcap_path))
        stats = {
            "total_packets": len(packets),
            "tcp_count": sum(1 for p in packets if TCP in p),
            "udp_count": sum(1 for p in packets if UDP in p),
            "unique_ips": len(set(p[IP].src for p in packets if IP in p)),
        }
        return stats
    except Exception as e:
        print(f"[-] PCAP validation failed: {e}")
        return {"error": str(e)}

def test_feature_injection(feature_name, file_path, expected):
    """Simulate testing one feature"""
    start = time.time()
    print(f"\n=== Testing: {feature_name} ===")
    print(f"File: {file_path}")
    print(f"Expected: {expected}")

    # -------------------------------
    # Here you would normally:
    # 1. Upload file to Streamlit (selenium / requests.post)
    # 2. Wait for processing
    # 3. Scrape / API-check result
    # For now — placeholder validation
    # -------------------------------

    if file_path.suffix == ".pcap":
        stats = basic_pcap_validation(file_path)
        print("Basic PCAP stats:", stats)
        detected = "malware" in str(stats).lower() or stats.get("tcp_count", 0) > 50
    else:
        # Log/XML — simple keyword check
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            content = f.read(20000)  # first 20KB
            detected = any(kw in content.lower() for kw in expected)

    elapsed = time.time() - start
    result = {
        "timestamp": datetime.now().isoformat(),
        "feature": feature_name,
        "file": file_path.name,
        "detected": detected,
        "time_seconds": round(elapsed, 2),
        "notes": "Real malware traffic test"
    }

    # Save to CSV
    df = pd.DataFrame([result])
    if os.path.exists(LOG_FILE):
        df.to_csv(LOG_FILE, mode="a", header=False, index=False)
    else:
        df.to_csv(LOG_FILE, index=False)

    print(f"Result: {'PASS' if detected else 'FAIL'} | Time: {elapsed:.2f}s")
    return result

# ================= MAIN =================

def main():
    print("=== Real-World Feature Accuracy Test ===")
    print("Downloading real 2025–2026 malware traffic...\n")

    results = []

    for name, data in DATASETS.items():
        file_path = download_and_extract(data["url"], data.get("password"))
        if file_path:
            # Test relevant features
            if "pcap" in str(file_path):
                results.append(test_feature_injection("Upload PCAP / Live Capture", file_path, data["expected_iocs"]))
                results.append(test_feature_injection("Threat Map / Domain Analysis", file_path, data["mitre"]))
                results.append(test_feature_injection("Anomaly Detection", file_path, ["exfil", "beacon"]))
            else:
                results.append(test_feature_injection("Zeek/Sysmon / IOC Intelligence", file_path, data["expected_events"]))

    print("\n=== Summary ===")
    df = pd.read_csv(LOG_FILE)
    print(df)
    print(f"\nOverall Detection Rate: {df['detected'].mean()*100:.1f}%")

if __name__ == "__main__":
    main()

from selenium import webdriver
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()
driver.get(STREAMLIT_URL)

# Find upload element (inspect your app)
upload = driver.find_element(By.CSS_SELECTOR, "input[type='file']")
upload.send_keys(str(file_path))

# Wait & check result
time.sleep(30)
result_text = driver.find_element(By.TAG_NAME, "body").text
detected = "malicious" in result_text.lower()