#!/usr/bin/env python
from ast import arguments
from math import fabs
from tabnanny import verbose
import scapy.all as scapy
import optparse

def get_arguments():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Target IP /IP Range.")
    (options,arguments)=parser.parse_args()
    return options

def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]

    client_list= []
    for elements in answered_list:
        client_dic={"ip":elements[1].psrc,"mac": elements[1].hwsrc}
        client_list.append(client_dic)
    return client_list

def print_result(results_list[])):
    
    print("IP\t\t\t MAC ADDRESS\n-------------------------------------------------------")
    for client in results_list:
        print(client["ip"]+"\ttt"+client["mac"])

        

options = get_arguments()
scan_result=scan(options.target)
print_result(scan_result)
