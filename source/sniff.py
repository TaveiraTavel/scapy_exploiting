from scapy.all import sniff

def icmp_sniff():
    sniff(filter="icmp", count=5).summary()
