import sys 
import os 
import time
from collections import defaultdict 
from scapy.all import sniff, IP, TCP

THRESHOLD= 40
print(f"Threshold value: {THRESHOLD}")

def read_ip_file(filename):
    with open(filename, 'r') as f:
        ips= [line.strip() for line in f]
    return set(ips)

def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80: # It checks if the packet has a TCP layer and the destination port of the packet is port 80 (which is standard fo the HTTP traffic)
        payload = packet[TCP].payload # Extracts the payload (data) of the TCP layer
        return "GET /scripts/root.exe" in str(payload) # Converts the payload into string and checks if it has the path GET/scripts/root.exe -> if found True is returned
    return False # else false is returned 

def log_event(message):
    log_folder= "logs" # This is the name of the log folder where log files will be saved 
    os.makedirs(log_folder, exist_ok= True) # # Folder will be created if no alreaddy there 
    timestamp= time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()) # This tells the format of the time 
    log_file= os.path.join(log_folder, f"log_{timestamp}.txt") # 
    
    with open(log_file, "a") as file:
    	file.write(f"{message}\n")
    	
def packet_callback(packet):
	src_ip= packet[IP].src
	
	if src_ip in whitelist_ips:
		return
	
	if src_ip in blacklist_ips:
		os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
		log_event(f"Blocking blacklisted ip: {src_ip}")
		
	if is_nimda_worm(packet):
		print(f"Blocking Nimda source IP: {src_ip}")
		os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
		log_event(f"Blocking Nimda source Ip: {src_ip}")
		return
	
	packet_count[src_ip] += 1
	current_time= time.time()
	time_interval= current_time - start_time[0]
	
	if time_interval >= 1:
		for ip, count in packet_count.items():
			packet_rate= count / time_interval
			if packet_rate > THRESHOLD and ip not in blocked_ips:
				print(f"Blocking Ip: {ip}, Packet rate: {packet_rate}")
				os.system(f"iptables -A INPUT -s {ip} -j DROP")
				log_event(f"Blocking Ip: {ip}, Packet rate: {packet_rate}")
				blocked_ips.add(ip)
				
		packet_count.clear()
		start_time[0]= current_time
		
if __name__ == "__main__":
	if os.geteuid() != 0:
		print("This script requires root priveleges")
		sys.exit(1)
		
	whitelist_ips= read_ip_file("whitelist.txt")
	blacklist_ips= read_ip_file("blacklist.txt")
	
	packet_count= defaultdict(int)
	start_time= [time.time()]
	blocked_ips= set()
	
	print("Monitoring network traffic....")
	sniff(filter="ip", prn= packet_callback)
