import plotly.express as px
import pandas as pd
from datetime import datetime


def create_alerts_visualization(live_alerts):
    """
    Create a visualization of real-time alerts using Plotly, including severity and mitigation.
    Args:
        live_alerts (list): List of alert dictionaries
    Returns:
        plotly.graph_objects.Figure: A bar chart of alerts by type, status, and severity
    """
    if not live_alerts:
        return px.bar(title="No Alerts Detected")

    # Convert alerts to DataFrame
    alerts_df = pd.DataFrame(live_alerts)

    # Create a combined label for type, status, and severity
    alerts_df['type_status_severity'] = alerts_df.apply(
        lambda row: f"{row['type']} ({row['status']}, Severity: {row['severity']})", axis=1
    )

    # Handle missing 'mitigation' field with a default value
    if 'mitigation' not in alerts_df.columns:
        alerts_df['mitigation'] = 'None'
    else:
        alerts_df['mitigation'] = alerts_df['mitigation'].fillna('None')

    # Add mitigation count for mitigated alerts
    mitigated_df = alerts_df[alerts_df['status'] == 'Mitigated'].groupby('type')['mitigation'].apply(list).reset_index()
    mitigated_text = mitigated_df.apply(
        lambda row: f"{row['type']}: {', '.join(row['mitigation'])}", axis=1
    ).str.cat(sep='\n') if not mitigated_df.empty else "No mitigations applied."

    fig = px.bar(alerts_df, x='type_status_severity', title='Real-time Alerts by Type, Status, and Severity',
                 labels={'type_status_severity': 'Alert Type (Status, Severity)', 'count': 'Count'})
    fig.update_layout(
        annotations=[dict(
            text=f"Mitigations:\n{mitigated_text}",
            x=0, y=1.1, xref="paper", yref="paper", showarrow=False, font=dict(size=12)
        )]
    )
    return fig


def create_logs_timeline(logs):
    """
    Create a timeline chart of log events or threats using Plotly, including severity and mitigation.
    Args:
        logs (pd.DataFrame): DataFrame with columns 'timestamp', 'source', 'event_type', 'severity', 'status', 'mitigation'
    Returns:
        plotly.graph_objects.Figure: A scatter plot of log events
    """
    if logs is None or logs.empty:
        return px.scatter(title="No Log Data Available")

    # Ensure timestamp is in datetime format
    logs['timestamp'] = pd.to_datetime(logs['timestamp'])

    # Handle missing 'mitigation' field with a default value
    if 'mitigation' not in logs.columns:
        logs['mitigation'] = 'None'
    else:
        logs['mitigation'] = logs['mitigation'].fillna('None')

    # Create a combined event type for visualization, handling missing 'mitigation'
    logs['event_details'] = logs.apply(
        lambda row: f"{row['event_type']} ({row['status']}, Severity: {row['severity']})" +
                    (f", Mitigation: {row['mitigation']}" if row['mitigation'] != 'None' else ""), axis=1
    )

    fig = px.scatter(logs, x='timestamp', y='source', color='event_details',
                     title='Log/Threat Timeline',
                     labels={'timestamp': 'Time', 'source': 'Source IP', 'event_details': 'Event Details'})
    fig.update_layout(legend_title_text='Event Details')
    return fig