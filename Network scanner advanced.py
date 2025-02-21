import socket
import struct
from scapy.all import *
import nmap
import requests

def get_local_ip():
    hostname = socket.gethostname() #gets the system's hostname
    #using the hostname to get the local IP address
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def get_network_range(ip, subnet_mask="255.255.255.0"):
    #Convert IP address to binary form
    ip_bin = struct.unpack('!I', socket.inet_aton(ip))[0]
    #Convert subnet mask to binary form
    mask_bin = struct.unpack('!I', socket.inet_aton(subnet_mask))[0]
    #perform & operation
    network_bin = ip_bin & mask_bin
    #convert the result to CIDR notation to get the network ID
    network_ip = socket.inet_ntoa(struct.pack('!I', network_bin))
    return f"{network_ip}/24"

local_ip = get_local_ip()
network_range = get_network_range(local_ip)
print(f"Scanning network: {network_range}")

#Creates an ARP request packet targeting the network range
def scan_network(network_range):
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

devices = scan_network(network_range)
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")

# scanning for open ports (TCP and UDP)
def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024',arguments="-sV")
    nm.scan(ip, arguments="-sU -p 53,161,69")

    print(f"[*] Scanned IPs: {nm.all_hosts()}") 

    if ip not in nm.all_hosts():
        print(f"[!] No response from {ip}, skipping port scan.")
        return []

    if 'tcp' not in nm[ip]:
        print(f"[!] No TCP ports found on {ip}, skipping.")
        return []

    open_ports = []
    for port in nm[ip]['tcp']:
        if nm[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)

    return open_ports

#Scan vulnerabilities
#Open ports,running services and versions
def scan_vulnerabilities(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="--script vuln")

    vulnerabilities = []
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto]:
            state = nm[ip][proto][port]['state']
            service = nm[ip][proto][port].get('name', 'unknown')

            version = nm[ip][proto][port].get('version', 'Unknown')

            vulnerabilities.append({'port': port, 'state': state, 'service': service, 'version': version})

    return vulnerabilities


#Searches for known vulnerabilities by service name and version.
def check_cve(service, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query = f"{service} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 1}

    response = requests.get(base_url, params=params)

    if response.status_code == 200:
        data = response.json()
        if data["vulnerabilities"]:
            return data["vulnerabilities"][0]["cve"]["id"]
    return None

#Runs a port scan.
#If ports are open, runs a vulnerability scan
for device in devices:
    open_ports = scan_ports(device['ip'])
    print(f"IP: {device['ip']} - Open Ports: {open_ports}")

    if open_ports:
        vuln_results = scan_vulnerabilities(device['ip'])
        
        for vuln in vuln_results:
            print(f"Port: {vuln['port']}, State: {vuln['state']}, Service: {vuln['service']}, Version: {vuln['version']}")
            cve_id = check_cve(vuln['service'], vuln['version'])
            if cve_id:
                print(f"[!] Confirmed Vulnerability: {cve_id}")

