from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    log_attempt(request)
    # Simulate IoT device behavior
    return "IoT Device Simulation"

def log_attempt(request):
    with open("honeypot_logs.txt", "a") as file:
        file.write(f"Access from {request.remote_addr}\n")

def start_honeypot():
    app.run(port=5001, debug=False)

if __name__ == "__main__":
    start_honeypot()
