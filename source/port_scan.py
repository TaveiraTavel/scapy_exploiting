from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

def scan_ports(target_ip, first=1, last=1024):
    last += 1
    count = 0
    print(f'Escaneando as {last-first} portas...\n')
    for port in range(first, last):
        resp = sr1(IP(dst=target_ip) / TCP(dport=port, flags='S'), verbose=0)
        flag = resp['TCP'].flags
        if (flag != 'RA'):
            print(f'{port}/TCP   Aberta   flag={flag}')
            count += 1
    print(f'\nForam descobertas {count} portas abertas!')
