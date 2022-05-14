#!/usr/bin/env python
from ast import arguments
from math import fabs
from tabnanny import verbose
import scapy.all as scapy
import optparse
import csv

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
    
    //print("IP\t\t\t MAC ADDRESS\n-------------------------------------------------------")
    for client in results_list:
        print(client["ip"]+"\ttt"+client["mac"])

        

options = get_arguments()
scan_result=scan(options.target)
print_result(scan_result)


'''Reads and updates clients.csv.'''
def updateClientsFile(f, tempfile, clients):
    print("Updating clients.csv...")

    fields = ['IP', 'COUNT', 'STATUS', 'MAC', 'VENDOR', 'TIMESTAMP']
    reader = csv.DictReader(f, fieldnames=fields)
    writer = csv.DictWriter(tempfile, fieldnames=fields)
    header = next(reader) # = fields
    writer.writerow(header)

    row_list = list(reader)
    ip_mac_list = []
    for row in row_list:
        info = {'ip': row['IP'], 'mac': row['MAC']}
        ip_mac_list.append(info)

    updated_rows = []
    parser = manuf.MacParser(update=False)

    for client in clients:
        # New clients.
        if client not in ip_mac_list:
            row = {'IP': client['ip'],
                   'COUNT': 1,
                   'STATUS': "ACTIVE",
                   'MAC': client['mac'],
                   'VENDOR': getVendor(client['mac'], parser),
                   'TIMESTAMP': str(datetime.now())[:16]}
            updated_rows.append(row)
        # Updates old clients (COUNT++).
        else:
            idx = ip_mac_list.index(client)
            old_count = int(row_list[idx]['COUNT'])
            row_list[idx]['COUNT'] = old_count + 1

    # Old but inactive clients.
    for idx, old_client in enumerate(ip_mac_list):
        if not any(client == old_client for client in clients):
            row_list[idx]['STATUS'] = "INACTIVE"
        else:
            row_list[idx]['STATUS'] = "ACTIVE"

    updated_rows += row_list

    for row in updated_rows:
        writer.writerow(row)

'''Prints the updated content from clients.csv.'''
def print_clients(filename):
    print("-"*80)
    # Could've just returned the updated rows from updateClientsFile, but lazy.
    with open(filename, 'r') as f:
        active_devices = 0
        inactive_devices = 0
        new_devices = 0
        reader = csv.reader(f)
        # 0 - IP
        # 1 - COUNT
        # 2 - STATUS
        # 3 - MAC
        # 4 - VENDOR
        # 5 - TIMESTAMP
        for row in reader:
            if (row[2] == "ACTIVE"):
                active_devices += 1
            elif (row[2] == "INACTIVE"):
                inactive_devices += 1
            if (row[2] == "ACTIVE" and row[1] == "1"):
                new_devices += 1
            print('{:<15} {:<6} {:<9} {:<18} {:<10} {:<16}'.format(*row))

    print("-"*80)
    print("> Total devices:\t", active_devices + inactive_devices)
    print("> Active devices:\t", active_devices)
    print("> Inactive devices:\t", inactive_devices)
    print("> New devices:\t\t", new_devices)

def main(argv):
    own_ip = argv
    router_ip = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX", verbose=False).src
    print("> Your IP:\t\t", own_ip)
    print("> Default gateway:\t", router_ip)
    scan_res = scan(own_ip)

    filename = "clients.csv"
    tempfile = NamedTemporaryFile(mode='w', delete=False)

    with open(filename, "r") as f, tempfile:
        updateClientsFile(f, tempfile, scan_res)
    shutil.move(tempfile.name, filename)

    print_clients(filename)

if __name__ == "__main__":
    if len(sys.argv)==1:
        sys.exit("Error: run like 'sudo python network_scannner 172.21.x.xxx/yy'")
    main(sys.argv[1])
