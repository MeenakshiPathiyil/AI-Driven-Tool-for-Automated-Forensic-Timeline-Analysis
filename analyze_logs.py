import json
from collections import Counter
import pandas as pd
from t1003_detect import CredentialDumpingDetector
from t1110_detect import BruteForceDetector
from timeline_parser import LogParser

def run_analysis(df: pd.DataFrame, iocs=None, output_file: str = None):
    # Run T1110 and T1003 detection on the provided DataFrame and save results to a file.
    all_anomalies = []
    
    # Parse the DataFrame
    parsed_df = LogParser(df).parse()

    # Run T1110 (Brute Force) detection
    try:
        detector = BruteForceDetector(csv_file=None, output_file=None, time_window_minutes=5, event_threshold=5)
        t1110_anomalies = detector.detect_brute_force(parsed_df)
        all_anomalies.extend(t1110_anomalies)
    except Exception as e:
        print(f"Error running detect_t1110: {e}")

    # Run T1003 (Credential Dumping) detection
    try:
        detector = CredentialDumpingDetector(csv_file=None, output_file=None, time_window_minutes=5, event_threshold=3)
        t1003_anomalies = detector.detect_credential_dumping(parsed_df)
        all_anomalies.extend(t1003_anomalies)
    except Exception as e:
        print(f"Error running detect_t1003: {e}")

    # Generate summary
    summary = generate_summary(all_anomalies)

    # Save results to output_file 
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    "summary": summary,
                    "anomalies": all_anomalies
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving results to {output_file}: {e}")

    return {
        "summary": summary,
        "anomalies": all_anomalies,
        "output_file": output_file
    }

def generate_summary(anomalies):
    summary = {}
    summary["total_anomalies"] = len(anomalies)
    by_detector = Counter()
    by_user = Counter()
    by_host = Counter()
    times = []

    for anomaly in anomalies:
        # Handle different detection formats
        if "type" in anomaly:
            by_detector[anomaly["type"]] += 1
        if "username" in anomaly:
            by_user[str(anomaly["username"]).lower()] += 1
        if "ip_address" in anomaly:
            by_host[str(anomaly["ip_address"]).lower()] += 1
        elif "process_name" in anomaly and anomaly["process_name"] != "Unknown":
            by_host[str(anomaly["process_name"]).lower()] += 1
        if "time_range" in anomaly:
            try:
                start_time = anomaly["time_range"].split(" to ")[0]
                times.append(start_time)
            except:
                pass

    summary["by_detector"] = dict(by_detector)
    summary["by_user"] = dict(by_user)
    summary["by_host"] = dict(by_host)

    if times:
        pd_times = pd.to_datetime(times, errors='coerce')
        summary["time_range"] = {
            "start": str(pd_times.min()),
            "end": str(pd_times.max())
        }

    return summary


