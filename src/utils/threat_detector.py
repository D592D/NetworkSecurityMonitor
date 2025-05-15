import json
import os
from datetime import datetime, timedelta
import pandas as pd


def load_known_threats():
    """
    Load known threat patterns from JSON file

    Returns:
        dict: Dictionary containing threat patterns
    """
    try:
        with open("data/known_threats.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Return default threats if file doesn't exist
        return {
            "patterns": [
                {
                    "name": "Brute Force Attack",
                    "pattern": "failed login attempt",
                    "threshold": 5,
                    "timeframe": 300  # 5 minutes in seconds
                },
                {
                    "name": "Suspicious IP Access",
                    "pattern": "unauthorized access",
                    "threshold": 1,
                    "timeframe": 60
                },
                {
                    "name": "Data Exfiltration",
                    "pattern": "large data transfer",
                    "threshold": 3,
                    "timeframe": 600
                }
            ]
        }


def detect_threats(processed_logs):
    """
    Detect threats based on known patterns and log analysis

    Args:
        processed_logs (pd.DataFrame): DataFrame with columns 'source', 'details', 'timestamp'

    Returns:
        dict: Threat summary including detected threats and statistics

    Raises:
        ValueError: If input is not a DataFrame or missing required columns
    """
    if not isinstance(processed_logs, pd.DataFrame):
        raise ValueError("processed_logs must be a pandas DataFrame")

    required_cols = ['source', 'details', 'timestamp']
    missing_cols = [col for col in required_cols if col not in processed_logs.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns: {missing_cols}")

    threats = []
    known_threats = load_known_threats()

    # Group logs by source
    grouped_logs = processed_logs.groupby('source')

    for source, logs in grouped_logs:
        for threat_pattern in known_threats["patterns"]:
            matching_logs = logs[logs['details'].str.contains(
                threat_pattern["pattern"],
                case=False,
                na=False
            )]

            if len(matching_logs) >= threat_pattern["threshold"]:
                latest_log = matching_logs['timestamp'].max()
                timeframe_start = latest_log - timedelta(seconds=threat_pattern["timeframe"])
                logs_in_timeframe = matching_logs[
                    matching_logs['timestamp'] >= timeframe_start
                    ]

                if len(logs_in_timeframe) >= threat_pattern["threshold"]:
                    threat = {
                        "source": source,
                        "threat_type": threat_pattern["name"],
                        "occurrence_count": len(logs_in_timeframe),
                        "first_seen": logs_in_timeframe['timestamp'].min().strftime("%Y-%m-%d %H:%M:%S"),
                        "last_seen": latest_log.strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": calculate_severity(
                            len(logs_in_timeframe),
                            threat_pattern["threshold"]
                        )
                    }
                    threats.append(threat)

    threat_summary = {
        "total_threats": len(threats),
        "threats_by_severity": {
            "high": len([t for t in threats if t["severity"] == "high"]),
            "medium": len([t for t in threats if t["severity"] == "medium"]),
            "low": len([t for t in threats if t["severity"] == "low"])
        },
        "detected_threats": threats
    }

    return threat_summary


def calculate_severity(occurrence_count, threshold):
    """
    Calculate threat severity based on occurrence count and threshold

    Args:
        occurrence_count (int): Number of occurrences
        threshold (int): Minimum threshold for threat detection

    Returns:
        str: Severity level ('high', 'medium', 'low')
    """
    ratio = occurrence_count / threshold
    if ratio >= 3:
        return "high"
    elif ratio >= 2:
        return "medium"
    else:
        return "low"