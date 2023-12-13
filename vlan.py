from netmiko import ConnectHandler
import json

# Load device configuration from a JSON file
with open('config.json', 'r') as file:
    cisco_device = json.load(file)

# Establish a connection to the device
net_connect = ConnectHandler(**cisco_device)

# Entering enable mode
net_connect.enable()

# Configuration commands to send (example: creating VLAN 100)
commands = ['vlan 100', 'name Marketing']

# Sending configuration commands
output = net_connect.send_config_set(commands)

# Print the output
print(output)

# Close the connection
net_connect.disconnect()
