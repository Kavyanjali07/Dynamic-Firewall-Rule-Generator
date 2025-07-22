<<<<<<< HEAD
#Dynamic Firewall Rule Generator
A Python-based network security tool designed to monitor network traffic in real-time and dynamically generate firewall rules to block suspicious IPs and log security events.

#📘 Table of Contents
Overview
Features
System Components
How It Works
Usage Instructions
Dependencies
Architecture Diagram
Developer Notes

#📖 Overview
Traditional firewalls rely on static rule sets. This project brings intelligence to your system by detecting unusual patterns and automatically applying IPTables rules to block malicious IPs.

#✨ Features
🔍 Real-time network traffic monitoring

⚙️ Dynamic rule generation using predefined or learned thresholds

🛡️ Integration with iptables to block suspicious IPs

📊 Logging of all activities for audit and analysis

🖥️ Simple GUI for non-technical users

#🧩 System Components
File	              Purpose
gui.py	              Tkinter/Flask GUI for controlling the system
DynamicRule.py	    Core logic that analyzes traffic and generates rules
config.json	    Stores thresholds and runtime settings
firewall_real.db        Stores all applied firewall rules
network_security.db     Stores logs of anomalies and events

#⚙️ How It Works
Start Monitoring: The user starts traffic monitoring from the GUI.
=======
# 🔥 Dynamic Firewall Rule Generator

A Python-based GUI tool designed to monitor live network traffic, detect anomalies, and dynamically generate and apply firewall rules using `iptables`. Built with a strong emphasis on system security, usability, and extensibility.

---
## 🧠 Overview

The **Dynamic Firewall Rule Generator** actively monitors network packets in real-time. It detects suspicious activity, such as unauthorized IPs or unusual traffic, and generates firewall rules automatically to block threats on-the-fly.

---
## ✨ Key Features

- Real-time network packet monitoring
- Anomaly detection based on IP, port, and protocol behavior
- GUI interface for ease of use (built with `Tkinter`)
- Stores firewall rules in `SQLite` databases
- Applies rules using Linux `iptables`
- Configurable thresholds using `config.json`
- Threaded performance to avoid GUI freeze
- Log file for audit and debugging

---

**⚙️ How It Works**
>Start Monitoring: The user starts traffic monitoring from the GUI.
>>>>>>> 7d2008e (.)

>Traffic Analysis: The system uses tools like scapy and psutil to inspect network traffic.

>Anomaly Detection: Based on thresholds from config.json, suspicious activity is flagged.

>Firewall Rule Generation: A rule is generated and applied using iptables.

>Logging: All events and rules are logged into network_security.db.

<<<<<<< HEAD
#🚀 Usage Instructions
📥 1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/your-username/dynamic-firewall.git
cd dynamic-firewall

🛠️ 2. Create Virtual Environment (Kali/Ubuntu)
bash
Copy
Edit
sudo apt install python3.13-venv
python3 -m venv venv
source venv/bin/activate

🔧 3. Install Requirements
bash
Copy
Edit
pip install -r requirements.txt
# or install manually:
pip install flask flask_sqlalchemy scapy psutil

🔒 4. Run the Application
bash
Copy
Edit
sudo python3 gui.py
🔐 sudo is required because firewall manipulation via iptables needs root access.

#📦 Dependencies
Python 3.10+

Flask / Tkinter

SQLite3

iptables

scapy (for packet analysis)

psutil (for process & port mapping)

#🧠 Architecture Sketch
=======
#🧠 Architecture Sketch**
>>>>>>> 7d2008e (.)

          +---------------------+
          |  GUI (gui.py)       |
          +----------+----------+
                     |
                     v
          +---------------------+
          |  Core Logic         |
          |  (DynamicRule.py)   |
          +----------+----------+
                     |
        +------------+-------------+
        |                          |
        v                          v
<<<<<<< HEAD
        +---------------+        +--------------------+
        | config.json   |        |network_security.db |
        +---------------+        +--------------------+
               |
               v
     +----------------------+
     |  iptables (Firewall) |
     +----------------------+

#👨‍💻 Developer Notes
This tool works best in Linux environments.
The rule generator is kept simple now but can be integrated with ML-based detection.
All configuration is done through config.json — you can change thresholds without touching the code.
Check logs in network_security.db using any SQLite viewer.
=======
    +---------------+        +--------------------+
    | config.json   |        |network_security.db |
    +---------------+        +--------------------+
            |
            v
    +----------------------+
    |  iptables (Firewall) |
    +----------------------+

**🚀 Usage Instructions**
#📥 1. Clone the Repository
>bash
>Copy
>Edit
>git clone https://github.com/your-username/dynamic-firewall.git
>cd dynamic-firewall

#🛠️ 2. Create Virtual Environment (Kali/Ubuntu)
>bash
>Copy
>Edit
>sudo apt install python3.13-venv
>python3 -m venv venv
>source venv/bin/activate

#🔧 3. Install Requirements
>bash
>Copy
>Edit
>pip install -r requirements.txt

 or install manually:
>pip install flask flask_sqlalchemy scapy psutil

#🔒 4. Run the Application
>bash
>Copy
>Edit
>sudo python3 gui.py
🔐 sudo is required because firewall manipulation via iptables needs root access.

**📦 Dependencies**
>Python 3.10+
>Flask / Tkinter
>SQLite3
>iptables
>scapy (for packet analysis)
>psutil (for process & port mapping)


**👨‍💻 Developer Notes**
>This tool works best in Linux environments.

>The rule generator is kept simple now but can be integrated with ML-based detection.

>All configuration is done through config.json — you can change thresholds without touching the code.

>Check logs in network_security.db using any SQLite viewer.


>>>>>>> 7d2008e (.)
