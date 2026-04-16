from scapy.all import sniff, IP
import tkinter as tk
import threading
from datetime import datetime
import matplotlib.pyplot as plt

# AI
from sklearn.ensemble import IsolationForest
import numpy as np

# ---------------- GLOBAL VARIABLES ----------------
packet_count = {}
total_packets = 0
running = False

LOG_FILE = "alerts.log"
BLACKLIST_FILE = "blacklist.txt"

# AI MODEL
model = IsolationForest(contamination=0.1)
training_data = []
trained = False

# ---------------- BLACKLIST ----------------
def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f.readlines())
    except:
        return set()

blacklist = load_blacklist()

def add_to_blacklist(ip):
    blacklist.add(ip)
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")

# ---------------- LOGGING ----------------
def log_to_file(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

# ---------------- AI DETECTION ----------------
def ai_detect(count):
    global trained

    training_data.append([count])

    # Train after enough samples
    if len(training_data) > 30 and not trained:
        model.fit(training_data)
        trained = True

    if trained:
        prediction = model.predict([[count]])

        if prediction[0] == -1:
            return "🚨 AI Detected Anomaly"
        else:
            return "Normal"
    else:
        return "Learning..."

# ---------------- PACKET PROCESSING ----------------
def process_packet(packet):
    global total_packets

    if packet.haslayer(IP):
        src = packet[IP].src
        total_packets += 1

        # Block already blacklisted IP
        if src in blacklist:
            msg = f"{datetime.now()} | BLOCKED IP: {src}"
            output.insert(tk.END, msg + "\n")
            log_to_file(msg)
            return

        if src not in packet_count:
            packet_count[src] = 0
        
        packet_count[src] += 1

        # AI Detection
        attack_type = ai_detect(packet_count[src])

        msg = f"{datetime.now()} | {src} | {attack_type}"
        output.insert(tk.END, msg + "\n")
        output.see(tk.END)
        log_to_file(msg)

        # Auto block if anomaly
        if "Anomaly" in attack_type:
            add_to_blacklist(src)

        update_dashboard()

# ---------------- SNIFFING ----------------
def sniff_packets():
    global running
    sniff(prn=process_packet, store=False, stop_filter=lambda x: not running)

# ---------------- CONTROL ----------------
def start_sniffing():
    global running
    running = True
    output.insert(tk.END, "✅ Monitoring started...\n")

    thread = threading.Thread(target=sniff_packets)
    thread.daemon = True
    thread.start()

def stop_sniffing():
    global running
    running = False
    output.insert(tk.END, "⛔ Monitoring stopped...\n")

# ---------------- DASHBOARD ----------------
def update_dashboard():
    stats_text.set(
        f"Packets: {total_packets} | IPs: {len(packet_count)} | Blacklisted: {len(blacklist)}"
    )

# ---------------- GRAPH ----------------
def show_graph():
    ips = list(packet_count.keys())
    counts = list(packet_count.values())

    plt.bar(ips, counts)
    plt.xlabel("IP Address")
    plt.ylabel("Packet Count")
    plt.title("Network Traffic Analysis")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# ---------------- GUI ----------------
root = tk.Tk()
root.title("AI-Based IDS/IPS System")
root.geometry("850x550")

title = tk.Label(root, text="🧠 AI Intrusion Detection & Prevention System", font=("Arial", 16))
title.pack(pady=5)

stats_text = tk.StringVar()
stats_label = tk.Label(root, textvariable=stats_text, fg="blue")
stats_label.pack()

start_btn = tk.Button(root, text="Start Monitoring", bg="green", fg="white", command=start_sniffing)
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="Stop Monitoring", bg="red", fg="white", command=stop_sniffing)
stop_btn.pack(pady=5)

graph_btn = tk.Button(root, text="Show Graph", command=show_graph)
graph_btn.pack(pady=5)

output = tk.Text(root, height=22, width=100)
output.pack()

root.mainloop()