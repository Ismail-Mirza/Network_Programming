import scapy.all as scapy
import argparse
def scan(ip):
    #arp request
    arp_request=scapy.ARP(pdst=ip)
    #broadcast and create ethernet frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request #/ meaning append broadcast with arp_reques
    #sending arp request broadcast msg by srp function
    answer_packet=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    client_list = []
    for element in answer_packet:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
def print_result(result_list):
    print("IP\t\t\tMac Address\n........................................")
    for element in result_list:
        print(f"{element['ip']}\t\t{element['mac']}")
def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP range.")

    # tell this child to parse argument
    options= parser.parse_args()
    if not options.target:
        parser.error("Usages --target  ip use --help for more info.")

    return options


options = get_argument()
client=scan(options.target)
print_result(client)
