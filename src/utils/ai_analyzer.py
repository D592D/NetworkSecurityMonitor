import os
import openai
import pandas as pd
import json
from datetime import datetime
from typing import Dict, List, Any, Optional  # Import typing for clarity

# Configure OpenAI API key (prioritize environment variable)
openai.api_key = os.environ.get("OPENAI_API_KEY")  # Removed hardcoded key


def analyze_with_ai(data: pd.DataFrame) -> Dict[str, Any]:
    """
    Analyze network data (packets or logs) using OpenAI's API and return security insights.

    Args:
        data: DataFrame with relevant columns (timestamp, source, destination, type, etc.)

    Returns:
        A dictionary containing analysis results, including security score, risk level,
        anomalies, potential threats, recommendations, total entries analyzed,
        and timestamp range.  Returns a default error dictionary if the API key
        is missing or an error occurs.
    """
    if openai.api_key is None:
        print(
            "Warning: OpenAI API key not found in environment variables. AI analysis will be disabled."
        )
        return {
            "security_score": 5,
            "risk_level": "low",
            "anomalies": [],
            "potential_threats": [],
            "recommendations": [
                "Monitor and investigate further.  OpenAI API key is required for AI analysis."
            ],
            "total_entries_analyzed": len(data),
            "timestamp_range": {
                "start": data["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
                "end": data["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
            },
        }

    print(f"Analyzing data with OpenAI: {data.head().to_dict()}")  # Debug: Log input data
    try:
        # Ensure data is a pandas DataFrame
        if not isinstance(data, pd.DataFrame):
            raise ValueError("Input must be a pandas DataFrame")

        # Convert the DataFrame to a string for AI analysis
        data_text = data.to_string()

        # Use OpenAI API to analyze data
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # or "gpt-4" if available
            messages=[
                {
                    "role": "system",
                    "content": "You are a network security expert analyzing network data (packets or logs) to identify only obvious, malicious threats (e.g., Brute Force Attack, Data Exfiltration, Malware Communication, Suspicious IP Access) with clear evidence of intent or harm. Ignore normal traffic like web browsing, network broadcasts, or routine service communication. Provide detailed, actionable recommendations for mitigation (e.g., 'Block IP address X', 'Increase monitoring on source Y', 'Isolate system Z'). Return the response as a JSON object with fields: security_score (0-10), risk_level ('low'/'medium'/'high'), anomalies (list), potential_threats (list of dicts with source, type, severity), and recommendations (list of strings). If no threats are detected, return potential_threats as an empty list and include a recommendation to 'Monitor and investigate further.'",
                },
                {
                    "role": "user",
                    "content": f"Analyze the following network data for security threats:\n\n{data_text}",
                },
            ],
            temperature=0.7,
            max_tokens=1000,
        )

        # Extract the AI response and parse it as JSON
        analysis_text = response.choices[0].message.content.strip()
        print(f"OpenAI response: {analysis_text}")  # Debug: Log AI response

        # Attempt to parse the response as JSON
        try:
            analysis = json.loads(analysis_text)
        except json.JSONDecodeError:
            analysis = parse_text_analysis(analysis_text)

        # Ensure all strings in the analysis are UTF-8 encoded
        def ensure_utf8(data: Any) -> Any:  # Added type hint for inner function
            if isinstance(data, str):
                return data.encode("utf-8", errors="replace").decode("utf-8")
            elif isinstance(data, dict):
                return {k: ensure_utf8(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [ensure_utf8(item) for item in data]
            return data

        analysis = ensure_utf8(analysis)

        # Calculate basic stats
        total_entries = len(data)
        timestamp_range: Dict[str, Optional[str]] = {  # Added type hint
            "start": data["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
            if not data.empty
            else None,
            "end": data["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
            if not data.empty
            else None,
        }

        # Structure the final response
        result: Dict[str, Any] = {  # Added type hint for result
            "security_score": analysis.get("security_score", 5),  # Default to 5 if not specified
            "risk_level": analysis.get("risk_level", "low"),
            "anomalies": analysis.get("anomalies", []),
            "potential_threats": analysis.get("potential_threats", []),
            "recommendations": analysis.get(
                "recommendations", ["Monitor and investigate further"]
            ),  # Default recommendation
            "total_entries_analyzed": total_entries,
            "timestamp_range": timestamp_range,
        }

        print(f"AI Analysis Result: {result}")  # Debug: Log final result
        return result

    except openai.AuthenticationError as e:
        print(
            f"Error in analyze_with_ai: Authentication Error - Code: {e.status_code}, Message: {str(e)}"
        )
        return {
            "security_score": 5,
            "risk_level": "low",
            "anomalies": [],
            "potential_threats": [],
            "recommendations": [
                "Monitor and investigate further—API key issue detected, check https://platform.openai.com/account/api-keys"
            ],
            "total_entries_analyzed": len(data),
            "timestamp_range": {
                "start": data["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
                "end": data["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
            },
        }
    except openai.RateLimitError as e:
        print(f"Error in analyze_with_ai: Rate Limit Error - {str(e)}")
        return {
            "security_score": 5,
            "risk_level": "low",
            "anomalies": [],
            "potential_threats": [],
            "recommendations": [
                "Monitor and investigate further—Rate limit reached, reduce API calls or check limits"
            ],
            "total_entries_analyzed": len(data),
            "timestamp_range": {
                "start": data["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
                "end": data["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
            },
        }
    except Exception as e:
        print(f"Error in analyze_with_ai: General Error - {str(e)}")
        return {
            "security_score": 5,
            "risk_level": "low",
            "anomalies": [],
            "potential_threats": [],
            "recommendations": ["Monitor and investigate further—AI error occurred"],
            "total_entries_analyzed": len(data),
            "timestamp_range": {
                "start": data["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
                "end": data["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")
                if not data.empty
                else None,
            },
        }


def parse_text_analysis(text: str) -> Dict[str, Any]:  # Added type hint
    """
    Parse a text response from OpenAI into a structured dictionary.

    Args:
        text: The text response from OpenAI.

    Returns:
        A dictionary containing the parsed analysis.
    """
    result: Dict[str, Any] = {  # Added type hint for result
        "security_score": 5,  # Default value
        "risk_level": "low",
        "anomalies": [],
        "potential_threats": [],
        "recommendations": [
            "Monitor and investigate further"
        ],  # Default recommendation
    }

    lines = text.split("\n")
    for line in lines:
        line = line.strip()
        if "security score" in line.lower():
            try:
                score = int(line.split(":")[-1].strip())
                result["security_score"] = max(0, min(10, score))
            except (ValueError, IndexError):
                continue
        elif "risk level" in line.lower():
            risk = line.split(":")[-1].strip().lower()
            if risk in ["low", "medium", "high"]:
                result["risk_level"] = risk
        elif line.startswith("Anomaly:"):
            result["anomalies"].append(line.replace("Anomaly:", "").strip())
        elif (
            line.startswith("Threat:")
            and "source" in line
            and "type" in line
            and "severity" in line
        ):
            parts = line.replace("Threat:", "").strip().split(",")
            threat: Dict[str, str] = {}  # Added type hint for threat
            for part in parts:
                if "source" in part:
                    threat["source"] = part.split("=")[-1].strip()
                elif "type" in part:
                    threat["type"] = part.split("=")[-1].strip()
                elif "severity" in part:
                    threat["severity"] = part.split("=")[-1].strip()
            if threat:
                result["potential_threats"].append(threat)
        elif line.startswith("Recommendation:"):
            result["recommendations"].append(line.replace("Recommendation:", "").strip())

    return result