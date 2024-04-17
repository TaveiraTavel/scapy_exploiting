from scapy.all import *
import subprocess

subprocess.run('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP', shell=True)

RPORT = 8585

def phping_trigger(RADDR):

    seq,ack = 0,0
    
    print('> TCP - SYN')
    print('< TCP - SYN/ACK')
    pk_syn = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='S')
    pk_synack = sr1(pk_syn, verbose=0)

    seq = pk_synack['TCP'].ack
    ack = pk_synack['TCP'].seq + 1

    print('> TCP - ACK')
    print('> HTTP - GET /ping.php')
    print('< TCP - ACK')
    print('< HTTP - OK')
    pk_ack2 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A'), verbose=0)

    http_get = bytes.fromhex('474554202f70696e672e70687020485454502f312e310d0a486f73743a2039392e39392e39392e3235343a383538350d0a0d0a')
    pk_get = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='PA')
    pk_get = pk_get / Raw(load=http_get)
    ans, unans = sr(pk_get, multi=True, timeout=5, verbose=0)

    pk_ok = ans[1][1]

    seq = pk_ok['TCP'].ack
    ack = pk_ok['TCP'].seq + len(pk_ok['TCP'].payload)

    print('> TCP - ACK')
    print('< TCP - FIN/ACK')
    pk_ack3 = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A')
    pk_finack = sr1(pk_ack3, verbose=0)

    seq = pk_finack['TCP'].ack
    ack = pk_finack['TCP'].seq + 1

    print('> TCP - FIN/ACK')
    print('< TCP - ACK')
    pk_finack2 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='FA'), verbose=0)


