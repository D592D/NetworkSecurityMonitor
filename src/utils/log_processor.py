import pandas as pd
import io
import re
from datetime import datetime


def validate_log_format(content):
    """
    Validate the format of uploaded log files

    Args:
        content (str): Raw log file content

    Returns:
        bool: True if valid format, raises error otherwise

    Raises:
        ValueError: If format is invalid
    """
    if not content:
        raise ValueError("Empty log file detected")

    sample_lines = content.split('\n')[:5]
    valid_patterns = [
        r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',  # Mon DD HH:MM:SS
        r'\d{2}/\w{3}/\d{4}'  # DD/MMM/YYYY
    ]

    for line in sample_lines:
        if any(re.search(pattern, line) for pattern in valid_patterns):
            return True
    raise ValueError("Invalid log format. Logs must contain timestamps in a recognizable format")


def preprocess_logs(uploaded_file):
    """
    Preprocess uploaded log files into a standardized format

    Args:
        uploaded_file: File object from Streamlit uploader

    Returns:
        tuple: (pd.DataFrame, dict) - Processed logs and statistics

    Raises:
        Exception: If preprocessing fails
    """
    try:
        uploaded_file.seek(0)
        raw_content = uploaded_file.read().decode("utf-8", errors="ignore")
        print("🔍 Debugging: Raw file content (First 500 characters)")
        print(raw_content[:500])
        validate_log_format(raw_content)

        uploaded_file.seek(0)
        df = pd.read_csv(uploaded_file, encoding="utf-8", dtype=str, on_bad_lines="skip")

        if df.empty:
            raise ValueError("The CSV file is empty or contains no valid rows.")

        # Flexible column mapping
        column_mapping = {
            'time': 'timestamp',
            'src': 'source',
            'event': 'event_type',
            'description': 'details'
        }
        df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns}, inplace=True)

        expected_columns = ['timestamp', 'source', 'event_type', 'details']
        df.columns = expected_columns[:len(df.columns)]

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        if df['timestamp'].isna().all():
            raise ValueError("No valid timestamps found in the log file.")

        df = df.sort_values('timestamp')
        df = df.drop_duplicates()
        df = df.dropna(subset=['timestamp'])

        print("✅ Debugging: Final processed DataFrame")
        print(df.head())

        log_stats = {
            'total_entries': len(df),
            'unique_sources': df['source'].nunique(),
            'date_range': f"{df['timestamp'].min().date()} to {df['timestamp'].max().date()}",
            'event_types': df['event_type'].value_counts().to_dict()
        }

        return df, log_stats

    except Exception as e:
        print(f"❌ Error during preprocessing: {str(e)}")
        raise Exception(f"Error preprocessing logs: {str(e)}")


def parse_text_logs(content):
    # [Keeping this function unchanged as it was already robust]
    # ... (original code)
    pass


def determine_event_type(details):
    # [Keeping this function unchanged as it was already robust]
    # ... (original code)
    pass