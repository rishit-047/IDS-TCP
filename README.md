# Nimda Worm Detection and Mitigation System
A Python-based real-time network monitoring and intrusion prevention tool that uses `Scapy` to detect Nimda worm traffic and rate-based attacks. It blocks malicious IPs dynamically using `iptables` and maintains logs for all actions. Designed for Linux environments and useful in personal or enterprise-level security setups.


## Features
- **Real-Time Network Monitoring:** Monitors incoming packets on a specified network interface using `Scapy`.
- **Nimda Worm Detection:** The Nimda worm is a malicious payload that spreads via email, web servers, and shared network drives, often exploiting Windows IIS vulnerabilities. The path `/scripts/root.exe` is a known signature used by Nimda to attempt remote code execution on vulnerable IIS servers.Identifies traffic indicative of the Nimda worm (`GET /scripts/root.exe`) and blocks the source IP immediately. 
- **Rate-Based IP Blocking:** Detects and blocks IPs that exceed a specified packet rate threshold (default: 40 packets/sec).
- **Whitelist and Blacklist Support:** Trusted IPs (whitelist) are ignored; blacklisted IPs are blocked instantly.
- **Log Management:** Creates timestamped log files in a `logs/` directory for each event (detection/block).
- **Auto Folder Creation:** Automatically creates the `logs/` directory if not present.
- **Root Privilege Verification:** Ensures the script is run as root for `iptables` command execution.


## Requirements

### OS:
- Debian-based systems (Ubuntu, Kali, etc.)

### Python:
- Python 3.6 or higher

### Python Libraries:
- [scapy](https://scapy.readthedocs.io/) – For packet sniffing
- collections – For counting packet rates
- time, os, sys – Standard libraries

### System Tools:
- `iptables` – Must be installed and available (usually pre-installed on Linux)
- Root privileges – Required to modify `iptables` rules


## Installation Steps
### 1. Clone the Repository
      git clone https://github.com/rishit-047/Nimda-Detection-System.git
      cd Nimda-Detection-System

### 2. Install Required Python Packages
    pip install scapy

### 3. Create IP Lists

There is a file named `whitelist.txt` — add trusted IPs (one per line):
    
    127.0.0.1        
    192.168.1.1    

There is a file named `blacklist.txt` — add IPs you want to block immediately:

    10.10.10.10
    203.0.113.45

## Run the Script
- Make sure you're in the project directory and run:

      sudo python3 monitor.py
