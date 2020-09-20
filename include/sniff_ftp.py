from scapy.all import *
import sys,logging

class FTPSniff(object):
	def __init__(self,pcap_path=f"files/{self.x}-ftp.pcap", http_file=f"files/{self.x}-ftp.log",verbose=False):
		self.pcap_path = pcap_path
		self.http_file = http_file
		self.main_thread = None
		
	def check_login(self, pkt, username, passwd):
		if '230' in pkt[Raw].load:
			logging.debug("Login found")
			return True
		
	def check_for_ftp(self,pkt):
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].dport == 21 and pkt[TCP].sport == 21:
				return True
			else:
				return False
		else:
			return False
			