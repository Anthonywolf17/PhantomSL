from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
import subprocess
import socket
import requests
import time
from scapy.all import ARP, Ether, srp, IP, TCP, sr
import platform
import re

console = Console()

def scan_network(target_ip):
    """Scans the network for active devices using ARP requests."""
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        manufacturer = get_manufacturer(mac)
        clients.append({"ip": ip, "mac": mac, "hostname": hostname, "manufacturer": manufacturer})

    return clients

def get_hostname(ip):
    """Retrieve hostname via Reverse DNS, NetBIOS, or nmblookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass

    if platform.system() == "Windows":
        try:
            nbt_output = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
            match = re.search(r"(\S+)\s+<00>", nbt_output.stdout)
            if match:
                return match.group(1)
        except subprocess.TimeoutExpired:
            pass
    else:
        try:
            nb_output = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3)
            for line in nb_output.stdout.split("\n"):
                if "<00>" in line and "GROUP" not in line:
                    return line.split()[0]
        except subprocess.TimeoutExpired:
            pass

    return "Unknown"

def get_manufacturer(mac):
    """Lookup manufacturer from MAC address."""
    oui = mac[:8].upper().replace(":", "-")
    url = f"https://api.macvendors.com/{oui}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass

    return "Unknown"

def scan_ports_nmap(ip):
    """Scans all ports using Nmap (if installed)."""
    try:
        output = subprocess.run(["nmap", "-p-", "-T4", "-oG", "-", ip], capture_output=True, text=True, timeout=30)
        ports = re.findall(r"(\d+)/open", output.stdout)
        return ", ".join(ports) if ports else "None"
    except subprocess.TimeoutExpired:
        return "Nmap timed out"

def scan_ports_scapy(ip):
    """Scans all ports using Scapy (if Nmap is unavailable)."""
    open_ports = []
    for port in range(1, 1025):  # Scan first 1024 ports for speed
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr(packet, timeout=1, verbose=0)[0]

        for _, recv in response:
            if recv.haslayer(TCP) and recv[TCP].flags == 18:  # SYN-ACK received
                open_ports.append(str(port))

    return ", ".join(open_ports) if open_ports else "None"

def advanced_scan(target_ip):
    """Performs an advanced scan: scans hosts and all ports."""
    console.print("[yellow]Scanning network...[/yellow]")
    clients = scan_network(target_ip)

    for client in clients:
        ip = client["ip"]
        console.print(f"\n[bold cyan]Scanning ports on {ip}...[/bold cyan]")

        if platform.system() == "Windows":
            nmap_check = subprocess.run(["where", "nmap"], capture_output=True, text=True)
        else:
            nmap_check = subprocess.run(["which", "nmap"], capture_output=True, text=True)

        if nmap_check.returncode == 0:
            ports = scan_ports_nmap(ip)
        else:
            ports = scan_ports_scapy(ip)


        client["open_ports"] = ports

    return clients

def display_results(clients, advanced=False):
    """Displays network scan results in a table."""
    table = Table(title="Advanced Network Scan" if advanced else "Basic Network Scan")
    table.add_column("IP Address", justify="left", style="cyan", no_wrap=True)
    table.add_column("MAC Address", justify="left", style="magenta")
    table.add_column("Hostname", justify="left", style="yellow")
    table.add_column("Manufacturer", justify="left", style="green")

    if advanced:
        table.add_column("Open Ports", justify="left", style="red")

    for client in clients:
        if advanced:
            table.add_row(client["ip"], client["mac"], client["hostname"], client["manufacturer"], client["open_ports"])
        else:
            table.add_row(client["ip"], client["mac"], client["hostname"], client["manufacturer"])

    console.print(table)

def main():
    console.print("[bold cyan]Network Scanner - Basic & Advanced Modes[/bold cyan]")

    while True:
        console.print("\n[1] Basic Information Scan")
        console.print("[2] Advanced Scan (All Ports)")
        console.print("[3] Exit")

        choice = Prompt.ask("\nEnter your choice", choices=["1", "2", "3"])

        if choice in ["1", "2"]:
            target_ip = Prompt.ask("Enter the target network range (e.g., 192.168.1.0/24)")
            console.print("[yellow]Scanning... Please wait.[/yellow]")

            if choice == "1":
                clients = scan_network(target_ip)
                display_results(clients)
            elif choice == "2":
                clients = advanced_scan(target_ip)
                display_results(clients, advanced=True)

        elif choice == "3":
            console.print("[green]Exiting. Goodbye![/green]")
            break

if __name__ == "__main__":
    main()
