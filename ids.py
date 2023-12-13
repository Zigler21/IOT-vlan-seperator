import scapy.all as scapy
import pandas as pd
import threading
from urllib.parse import urlparse
import requests
from scapy.all import show_interfaces
from scapy.layers import http
show_interfaces()


class AnomalyIDS:
    def __init__(self, interface):
        self.interface = interface
        self.normal_traffic = pd.DataFrame()  # Placeholder for normal traffic patterns
        self.alerts = []

    def start_sniffing(self):
        try:
            threading.Thread(target=self.sniff_traffic).start()
        except Exception as e:
            print(f"Error starting sniffing: {e}")

    def sniff_traffic(self):
        try:
            scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)
        except Exception as e:
            print(f"Error sniffing traffic: {e}")

    def process_packet(self, packet):
        with open('packets.txt', 'a') as f:
            f.write(str(packet) + '\n')
        # Simplified analysis: For example, count packets per second and compare against a threshold
        # In a real-world scenario, you'd have a more complex analysis here
        if self.detect_iot_attack(packet):
            self.redirect_to_honeypot(packet)

    def detect_iot_attack(self, packet):
        # Logic to determine if the packet is targeting an IoT device
        return True  # Placeholder

    def redirect_to_honeypot(self, packet):
        honeypot_url = "http://localhost:5001"
        # This is a simplified and notional representation. Actual redirection would be more complex.
        try:
            if packet.haslayer(http.HTTPRequest):
                url = honeypot_url + urlparse(packet[http.HTTPRequest].Path.decode()).path
                requests.get(url)
        except Exception as e:
            print(f"Error redirecting to honeypot: {e}")

    class AnomalyIDS:
        def __init__(self, interface):
            self.interface = interface
            self.normal_traffic = pd.DataFrame()  # Placeholder for normal traffic patterns
            self.alerts = []

        def start_sniffing(self):
            try:
                threading.Thread(target=self.sniff_traffic).start()
            except Exception as e:
                print(f"Error starting sniffing: {e}")

        def sniff_traffic(self):
            try:
                scapy.sniff(iface=self.interface, store=False, prn=self.process_packet)
            except Exception as e:
                print(f"Error sniffing traffic: {e}")

        def process_packet(self, packet):
            with open('packets.txt', 'a') as f:
                f.write(str(packet) + '\n')
            # Simplified analysis: For example, count packets per second and compare against a threshold
            # In a real-world scenario, you'd have a more complex analysis here
            if self.detect_iot_attack(packet):
                self.redirect_to_honeypot(packet)

        def detect_iot_attack(self, packet):
            # Logic to determine if the packet is targeting an IoT device
            if packet.haslayer(http.HTTPRequest):
                url = urlparse(packet[http.HTTPRequest].Path.decode()).path
                if url == '/':
                    print('hello')
                    return True
            elif packet.haslayer(http.HTTPResponse):
                # Check for specific headers or content in the response
                if packet[http.HTTPResponse].Content == 'application/json':
                    return True
            return False

        def redirect_to_honeypot(self, packet):
            honeypot_url = "http://localhost:5001"
            # This is a simplified and notional representation. Actual redirection would be more complex.
            try:
                if packet.haslayer(http.HTTPRequest):
                    url = honeypot_url + urlparse(packet[http.HTTPRequest].Path.decode()).path
                    requests.get(url)
            except Exception as e:
                print(f"Error redirecting to honeypot: {e}")

        def detect_anomaly(self, traffic_data):
            # Placeholder for anomaly detection logic
            # Compare 'traffic_data' with 'normal_traffic' patterns
            pass

        def log_alert(self, message):
            self.alerts.append(message)
            # todo: add to a log file on a server
            pass

    # Create an instance of AnomalyIDS and start sniffing
    ids = AnomalyIDS("Software Loopback Interface 1")  # replace "eth0" with your network interface
    ids.start_sniffing()
