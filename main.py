from flask import Flask, render_template, request
import scapy.all as scapy
import nmap
import socket
import os
import sys
import pandas as pd
from sqlalchemy import create_engine
from ids import AnomalyIDS


# Initialize Flask app for user interface
app = Flask(__name__)

#ids = AnomalyIDS("phy0")

# Database engine 
engine = create_engine('sqlite:///devices.db')
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Process login
        pass
    return render_template('login.html')

@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        # Code to add a new device
        pass
    return render_template('add_device.html')

@app.route('/devices', methods=['GET', 'POST'])
def devices():
    # Code to retrieve devices from database
    return render_template('devices.html', devices=devices) # Pass devices to the template

if __name__ == '__main__':    
    app.run( debug=True, host='0.0.0.0')
    

