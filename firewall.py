import os
import signal
from scapy.all import sniff, IP

# Define the blacklist of IPs
blacklist = {'8.8.8.8'}
print(f"Blocked IPs: {blacklist}")
print("Starting Firewall Simulation...")

# Track added rules to clean up later
added_rules = set()

def block_ip(ip):
    if ip not in added_rules:
        print(f"[BLOCKING] Blocking IP: {ip}")
        os.system(f'netsh advfirewall firewall add rule name="Blocked {ip}" dir=out action=block remoteip={ip}')
        added_rules.add(ip)

def unblock_all():
    print("Cleaning up and removing all firewall rules...")
    for ip in added_rules:
        print(f"[REMOVING] Removing block rule for {ip}")
        os.system(f'netsh advfirewall firewall delete rule name="Blocked {ip}"')
    added_rules.clear()

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if src_ip in blacklist or dst_ip in blacklist:
            print(f"[BLOCKED] Packet from {src_ip} to {dst_ip}")
            block_ip(src_ip if src_ip in blacklist else dst_ip)
        else:
            print(f"[ALLOWED] Packet from {src_ip} to {dst_ip}")

def cleanup_on_exit(signum, frame):
    unblock_all()
    print("Exiting...")
    exit(0)

# Handle Ctrl+C to clean up rules
signal.signal(signal.SIGINT, cleanup_on_exit)

# Start sniffing packets
target_interface = 'Wi-Fi' # Adjust this based on your actual interface
sniff(iface=target_interface, filter="ip", prn=packet_handler, store=0)
