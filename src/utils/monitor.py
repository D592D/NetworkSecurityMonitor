import scapy.all as scapy
import pandas as pd
import threading
import time
from datetime import datetime
import streamlit as st
from utils.ai_analyzer import analyze_with_ai


class SecurityMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.lock = threading.Lock()  # For thread safety
        self.live_alerts = []  # Shared list for alerts
        self.analyze_with_ai = None

    def start_monitoring(self):
        with self.lock:
            self.is_monitoring = True
            self.live_alerts = []  # Reset alerts on start to prevent accumulation
            print("🔍 Starting Monitoring...")
            print(f"Debug - Set is_monitoring to True and reset live_alerts")
            threading.Thread(target=self._sniff_packets, args=("Wi-Fi",), daemon=True).start()

    def stop_monitoring(self):
        with self.lock:
            self.is_monitoring = False
            print("🛑 Stopping Monitoring...")

    def is_monitoring_active(self):
        with self.lock:
            return self.is_monitoring

    def get_monitoring_status(self):
        with self.lock:
            return {"is_monitoring": self.is_monitoring, "live_alerts": self.live_alerts}

    def set_analysis_function(self, analyze_ai):
        self.analyze_with_ai = analyze_ai

    def _sniff_packets(self, interface):
        print(f"🔍 Starting packet sniffing on interface: {interface}")
        try:
            scapy.sniff(iface=interface, prn=self._process_packet, store=0)
        except Exception as e:
            print(f"Error in packet sniffing: {str(e)}")

    def _process_packet(self, packet):
        if not self.is_monitoring or not packet.haslayer(scapy.IP):
            return
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = "TCP" if packet[scapy.IP].proto == 6 else "UDP" if packet[scapy.IP].proto == 17 else "Other"

        alert = {
            'timestamp': datetime.now(),
            'type': 'Network Anomaly',  # Default type; AI will refine this
            'source': src_ip,
            'destination': dst_ip,
            'protocol': protocol,
            'status': 'Active',
            'severity': 'low'  # Default severity; AI will update
        }
        print(f"🔍 Processed packet: {src_ip} → {dst_ip} ({protocol})")

        # Analyze with AI if available, handle errors with detailed logging
        if self.analyze_with_ai:
            alert_data = pd.DataFrame([alert])
            try:
                print(f"Attempting AI analysis for packet: {alert}")  # Debug: Log before AI call
                ai_result = self.analyze_with_ai(alert_data)
                print(f"AI Result for packet: {ai_result}")  # Debug: Log AI result
                if ai_result and 'potential_threats' in ai_result and ai_result['potential_threats']:
                    for threat in ai_result['potential_threats']:
                        if threat.get('source') == src_ip and threat.get('type') != 'Network Anomaly':
                            alert['type'] = threat['type']
                            alert['severity'] = threat.get('severity', 'low')
                            if 'recommendations' in ai_result and ai_result['recommendations']:
                                alert['mitigation'] = ai_result['recommendations'][0]  # Use first recommendation
                                alert['status'] = 'Mitigated'
                            print(f"🚨 AI Identified and Mitigated Threat: {alert}")
                            break
                    else:
                        print(f"🚨 AI Identified Anomaly (No Specific Threat): {alert}")
                else:
                    print(f"🚨 AI Identified Anomaly (No Specific Threat, Empty Threats): {alert}")
            except Exception as e:
                print(f"Error processing packet with AI: {str(e)}")
                alert['status'] = 'Active'  # Default to Active if AI fails
                print(f"🚨 AI Failed - Identified Anomaly: {alert}")

        with self.lock:
            # Deduplicate alerts (same source, destination, type, and status within 5 seconds)
            current_time = datetime.now()
            deduplicated = True
            for existing_alert in self.live_alerts:
                if (existing_alert['source'] == alert['source'] and
                        existing_alert['destination'] == alert['destination'] and
                        existing_alert['type'] == alert['type'] and
                        existing_alert['status'] == alert['status'] and
                        (current_time - existing_alert['timestamp']).total_seconds() < 5):
                    deduplicated = False
                    break
            if deduplicated:
                self.live_alerts.append(alert)
                print(f"🔄 Updated live_alerts with new alert: {alert}")
                # Limit to last 100 alerts to prevent overwhelming
                if len(self.live_alerts) > 100:
                    self.live_alerts = self.live_alerts[-100:]

    def reset_alerts(self):
        """Manually reset live alerts if needed"""
        with self.lock:
            self.live_alerts = []
            print("🔄 Reset live_alerts manually")