from flask import Flask, render_template, request
import scapy.all as scapy
import nmap
import socket
import os
import threading
import sys
import pandas as pd
from sqlalchemy import create_engine
from ids import AnomalyIDS
from http.client import HTTPConnection as http
from urllib.parse import urlparse
import requests
from flask import Flask, redirect
from scapy.all import sniff, ARP
import subprocess
import sqlite3
from getmac import get_mac_address
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


# Initialize Flask app for user interface
app = Flask(__name__)
app.secret_key = 'test1234#@!1D'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

honeypot_url = 'http://0.0.0.0'  # replace with your actual URL

iotpacket = 'iotpackets.csv'
normalpacket = 'normalpackets.csv'

packet = AnomalyIDS("phy0")

#ids = AnomalyIDS("phy0")k

class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Database engine 
if not os.path.exists('devices.db'): 
    engine = create_engine('sqlite:///devices.db')
    conn = sqlite3.connect('devices.db')
else:
# Connect to SQLite database (or create it if it doesn't exist)
    conn = sqlite3.connect('devices.db')

# Create a cursor
c = conn.cursor()

# Create table
# Check if the table already exists
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'")
table_exists = c.fetchone()

if not table_exists:
    c.execute('''
        CREATE TABLE devices
        (mac_address text, ip_address text, honeypot_status integer)
    ''')

# Commit the changes and close the connection
conn.commit()
conn.close()

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Validate the username and password
        if username == 'admin' and password == 'password':  # Replace with actual validation
            user = User(1)
            login_user(user)
            return redirect('/devices')
    return render_template('login.html')

@app.route('/add_device', methods=['GET', 'POST'])
@login_required
def add_device():
    # Get the MAC address using the IP address
    ip_address = "192.168.0.1"  # Replace with the actual IP address
    if request.method == 'POST':
        mac_address = request.form['mac_address']
        ip_address = request.form['ip_address']
        honeypot_status = int(request.form['honeypot_status'])

        # Connect to the database
        conn = sqlite3.connect('devices.db')
        c = conn.cursor()

        # Insert the device into the table
        c.execute('''
            INSERT INTO devices VALUES (mac_address text, ip_address text, honeypot_status integer)
        ''', (mac_address, ip_address, honeypot_status))

        # Commit the changes and close the connection
        conn.commit()
        conn.close()

    return render_template('add_device.html')

@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    # Connect to the database
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()

    # Fetch all devices from the database
    c.execute("SELECT * FROM devices")
    devices = c.fetchall()

    # Close the connection
    conn.close()

    # Pass devices to the template
    return render_template('devices.html', devices=devices)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
    
def process_packet(packet):
    # Process the packet data
    # This is just a placeholder. Replace with your actual processing code.
    if packet:  # Replace this condition with your actual condition
        return True
    else:
        return False


def return_to_honeypot(packet):
    # This is a simplified and notional representation. Actual redirection would be more complex.
    try:
        if packet.haslayer(http.HTTPRequest):
            url = honeypot_url + urlparse(packet[http.HTTPRequest].Path.decode()).path
            requests.get(url)
    except Exception as e:
        print(f"Error redirecting to honeypot: {e}")

def process_packet(packet):
    # Check if it's an IoT device
    if is_iot_device(packet):
        # If it is, isolate it
        isolate_device(packet)

def is_iot_device(packet):
    # Replace with actual logic to identify IoT devices
    return packet.haslayer(ARP) and (packet[ARP].psrc.startswith('192.168.') or packet[ARP].psrc.startswith('10.0.'))

def isolate_device(packet):
    # Replace with actual logic to isolate the device

    print(f"Isolating device {packet[ARP].psrc}")



def isolate_device(packet):
        # Get the IP address of the IoT device
        ip_address = packet[ARP].psrc

        # Add a rule to iptables to drop all packets to/from this IP address
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "BLOCK"])
        subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"])

        print(f"Isolated device {ip_address}")

def redirect_to_honeypot(packet):
    # Process the packet if necessary
    # ...

    # Define the honeypot URL
    honeypot_url = 'http://0.0.0.0'  # replace with your actual URL

    # Redirect to the honeypot URL
    return redirect(honeypot_url, code=302)


if __name__ == '__main__':    
    app.run( debug=True, host='127.0.0.1')

    # Start sniffing packets
    sniff(prn=process_packet)
    if packet == "iotpackets.csv":
        redirect_to_honeypot(process_packet) and isolate_device(process_packet) #send iot packets to the void address
    else:
        pass
