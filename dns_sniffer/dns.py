import dns_sniffer,sys,termcolor
options=dns_sniffer.Dns.get_argument()
# print(options.netcut)
if options.netcut:
    try:
        dns_sniffer.Dns.foreign_settings()
        dns_sniffer.Dns.queues(dns_sniffer.Dns.net_cut)
    except KeyboardInterrupt:
        print("\n[-] Detected ctrl c ...Resetting iptables rule...")
        dns_sniffer.Dns.restore_foreign_settings()
elif options.intercept:
    # print("intercept",options.intercept)
    # print("local",options.local,type(options.local))
    if options.local=="0":
        if options.extension and options.location:
            try:
                dns_sniffer.Dns.local_settings()
                dns_sniffer.Dns.queues(dns_sniffer.Dns.file_interceptor)
            except KeyboardInterrupt:
                print("\n[-] Detected ctrl c ...Resetting iptables rule...")
                dns_sniffer.Dns.restore_local_settings()
        else:
            termcolor.cprint("[-] Usages -l 0 -e extension -loc location \n Do -h for more info","red")
            dns_sniffer.Dns.restore_local_settings()
    elif options.local =="1":
        if options.extension and options.location:
            try:
                dns_sniffer.Dns.foreign_settings()
                dns_sniffer.Dns.queues(dns_sniffer.Dns.file_interceptor)
            except KeyboardInterrupt:
                print("\n[-] Detected ctrl c ...Resetting iptables rule...")
                dns_sniffer.Dns.restore_foreign_settings()
        else:
            termcolor.cprint("[-] Usages -l 1 -e extension -loc location \n Do -h for more info","red")
            dns_sniffer.Dns.restore_foreign_settings()
    else:
        termcolor.cprint("[-] Usages -l 0 or 1 -e extension -loc location \n Do -h for more info","red")
elif options.watch_packet:
    # print("intercept",options.intercept)
    # print("local",options.local,type(options.local))
    if options.local=="0":
        try:
            dns_sniffer.Dns.local_settings()
            dns_sniffer.Dns.queues(dns_sniffer.Dns.monitor)
        except KeyboardInterrupt:
            print("\n[-] Detected ctrl c ...Resetting iptables rule...")
            dns_sniffer.Dns.restore_local_settings()

    elif options.local =="1":
        try:
            dns_sniffer.Dns.foreign_settings()
            dns_sniffer.Dns.queues(dns_sniffer.Dns.monitor)
        except KeyboardInterrupt:
            print("\n[-] Detected ctrl c ...Resetting iptables rule...")
            dns_sniffer.Dns.restore_foreign_settings()
    else:
        termcolor.cprint("[-] Usages -l 0 or 1 \n Do -h for more info","red")
        dns_sniffer.Dns.restore_foreign_settings()

else:
    termcolor.cprint("[+] Usages -nc 1 --For netcut the victim","red")
    termcolor.cprint("[+] Usages -fi 1  --For file interceptor\n[+] Do -fi 1 -h for more info","red")
    termcolor.cprint("[+] Usages -wp 1  --For monitor packet","red")
    sys.exit()
