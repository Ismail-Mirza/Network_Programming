from  injector import  *
# reroute iptables rule for sslstrip forwarding from 80 to 10000
#iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

if __name__ == "__main__":
    Inj.queue(Inj.code_process,0)