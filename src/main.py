


import streamlit as st
import pandas as pd
from utils.monitor import SecurityMonitor
from streamlit_autorefresh import st_autorefresh
from datetime import datetime
from utils.visualizer import create_alerts_visualization, create_logs_timeline
from ipaddress import ip_address, ip_network
import socket
from collections import defaultdict
import subprocess
import webbrowser
import os
import time
import psutil

st.set_page_config(page_title="Real-Time Network Security Monitor", layout="wide")

if 'monitor' not in st.session_state:
    st.session_state.monitor = SecurityMonitor()

# Cache for DNS resolutions to avoid repeated lookups
dns_cache = defaultdict(str)


def is_local_ip(ip_str):
    """
    Check if an IP address is within a local/private range.
    """
    try:
        ip = ip_address(ip_str)
        private_ranges = [
            ip_network('192.168.0.0/16'),
            ip_network('10.0.0.0/8'),
            ip_network('172.16.0.0/12')
        ]
        return any(ip in network for network in private_ranges)
    except ValueError:
        return False


def get_dns_name(ip_str):
    """
    Resolve IP to DNS name, using cache to avoid repeated lookups.
    """
    if not ip_str in dns_cache:
        try:
            dns_name = socket.gethostbyaddr(ip_str)[0]
            dns_cache[ip_str] = dns_name
        except (socket.herror, socket.gaierror):
            dns_cache[ip_str] = "Unknown"
    return dns_cache[ip_str]


def is_port_in_use(port):
    """
    Check if a port is already in use.
    """
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return True
    return False


def launch_vulnerability_scanner():
    """
    Launch the vulnerability scanner app in a separate process on port 5001.
    """
    try:
        # Path to vulnerability_scanner.py
        scanner_path = "C:\\Users\\Lenovo\\PycharmProjects\\NetorkAI\\src\\utils\\vulnerability_scanner.py"
        if not os.path.exists(scanner_path):
            st.error(f"Vulnerability scanner script not found at {scanner_path}")
            return

        # Check if port 5001 is in use
        port = 5001
        if is_port_in_use(port):
            st.error(f"Port {port} is already in use. Please free the port or use a different one.")
            return

        # Launch the scanner app on port 5001
        cmd = [
            "streamlit", "run", scanner_path,
            "--server.address", "192.168.0.18",
            "--server.port", str(port)
        ]
        st.write(f"Launching Vulnerability Scanner with command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True
        )

        # Wait for the app to start (give it a few seconds)
        time.sleep(3)

        # Check if the process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            st.error(f"Failed to start Vulnerability Scanner. Exit code: {process.returncode}")
            if stdout:
                st.write("stdout:", stdout)
            if stderr:
                st.write("stderr:", stderr)
            return

        # Open the scanner app in a new browser tab
        scanner_url = f"http://192.168.0.18:{port}"
        webbrowser.open_new_tab(scanner_url)
        st.success(f"Vulnerability Scanner launched in a new tab: {scanner_url}")
    except Exception as e:
        st.error(f"Failed to launch Vulnerability Scanner: {str(e)}")


def main():
    st.title("🛡️ Real-Time Network Security Monitoring System")

    # Sidebar controls
    st.sidebar.header("Monitoring Controls")
    if st.session_state.monitor.is_monitoring:
        if st.sidebar.button("🛑 Stop Monitoring"):
            st.session_state.monitor.stop_monitoring()
            st.rerun()
    else:
        if st.sidebar.button("▶️ Start Monitoring"):
            st.session_state.monitor.start_monitoring()
            st.rerun()

    # Add Run Scan button under Monitoring Controls
    if st.sidebar.button("🔍 Vulnerability Run Scan"):
        launch_vulnerability_scanner()

    # Tabs (removed Vulnerability Scan tab)
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Real-time Alerts", "Threat Analysis", "Visualizations", "Configuration", "External IPs"])

    with tab1:
        st.header("Real-time Network Alerts")
        st_autorefresh(interval=2000, key="real_time_refresh")

        status = "Active" if st.session_state.monitor.is_monitoring else "Inactive"
        st.metric("Monitoring Status", status)

        live_alerts = st.session_state.monitor.live_alerts
        total_alerts = len(live_alerts)
        active_alerts = len([a for a in live_alerts if a['status'] == 'Active'])
        mitigated_alerts = len([a for a in live_alerts if a['status'] == 'Mitigated'])

        cols = st.columns(4)
        cols[0].metric("Total Alerts", total_alerts)
        cols[1].metric("Active Alerts", active_alerts)
        cols[2].metric("Mitigated Alerts", mitigated_alerts)
        cols[3].metric("Last Update", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        st.subheader("Live Alerts")
        if live_alerts:
            for alert in reversed(live_alerts[-10:]):
                st.write(
                    f"🚨 {alert['type']} - {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {alert['source']} → {alert['destination']} ({alert['protocol']}) - Severity: {alert['severity']}, Status: {alert['status']}")
                if 'mitigation' in alert:
                    st.write(f"**Mitigation:** {alert['mitigation']}")
        else:
            st.info("No live alerts detected yet.")

        if total_alerts > 0 and mitigated_alerts == 0 and all(
                a['severity'] == 'low' and a['status'] == 'Active' for a in live_alerts):
            st.success(
                "No significant threats detected. Network activity appears normal. Continue monitoring for anomalies.")

    with tab2:
        st.header("Threat Analysis")
        # Add threat analysis logic here if needed

    with tab3:
        st.header("Visualizations")
        live_alerts = st.session_state.monitor.live_alerts
        fig_alerts = create_alerts_visualization(live_alerts)
        st.plotly_chart(fig_alerts, use_container_width=True)

        alerts_df = pd.DataFrame(live_alerts)
        if not alerts_df.empty:
            if 'mitigation' not in alerts_df.columns:
                alerts_df['mitigation'] = 'None'
            logs_df = alerts_df[['timestamp', 'source', 'type', 'severity', 'status', 'mitigation']].rename(
                columns={'type': 'event_type'})
            fig_timeline = create_logs_timeline(logs_df)
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("No data available for timeline visualization.")

    with tab4:
        st.header("Configuration")
        # Add configuration options here if needed

    with tab5:
        st.header("External IPs")
        st_autorefresh(interval=2000, key="external_ips_refresh")

        live_alerts = st.session_state.monitor.live_alerts
        if live_alerts:
            external_alerts = [alert for alert in live_alerts if not is_local_ip(alert['source'])]
            if external_alerts:
                st.subheader(
                    f"External Source IPs ({len(external_alerts)} total, {len(set(alert['source'] for alert in external_alerts))} unique detected)")
                unique_external_ips = set(alert['source'] for alert in external_alerts)
                external_ip_dns = {ip: get_dns_name(ip) for ip in unique_external_ips}
                for alert in reversed(external_alerts[-10:]):
                    dns_name = external_ip_dns[alert['source']]
                    st.write(
                        f"🌐 {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: {alert['source']} ({dns_name}) → {alert['destination']} ({alert['protocol']}) - Severity: {alert['severity']}, Status: {alert['status']}")
                    if 'mitigation' in alert:
                        st.write(f"**Mitigation:** {alert['mitigation']}")
                unique_external_ips_count = len(unique_external_ips)
                st.metric("Unique External IPs", unique_external_ips_count)
            else:
                st.info("No external source IPs detected.")
        else:
            st.info("No alerts available to analyze for external IPs.")


if __name__ == "__main__":
    main()
