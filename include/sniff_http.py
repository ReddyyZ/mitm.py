from scapy.all import *
from scapy.layers.http import HTTPRequest
from multiprocessing import Process
from colorama import init, Fore
import logging,random

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

class HttpSniff(object):
	x = random.randint(1000,9999)
	def __init__(self,pcap_path=f"files/{x}-http.pcap", http_file=f"files/{x}-http.log",verbose=False):
		self.pcap_path = pcap_path
		self.http_file = http_file
		self.main_thread = None

		init()
		logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
		logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
		logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
		logging.addLevelName(logging.DEBUG, f"[{cyan}**{reset}]")
		logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.WARNING)
		
	def handle_packet(self, pkt):
		if pkt.haslayer(HTTPRequest):
		    wrpcap(self.pcap_path, pkt, append=True)
		
		    url    = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
		    ip     = pkt[IP].src
		    method = pkt[HTTPRequest].Method.decode()
		    raw    = None
		    if pkt.haslayer(Raw) and method == "POST":
			    raw = pkt[Raw].load
		
		    with open(self.http_file,"a+") as fd:
			    fd.write(f"{method} from {ip} to {url} {f'- Data: {raw}' if raw else ''}\n")
		
		    logging.info(f"HTTP {method} request from {ip} to {url}")
		
	def sniff_thread(self):
		sniff(filter="port 80", prn=self.handle_packet)
		
	def start(self):
		self.main_thread = Process(target=self.sniff_thread)
		self.main_thread.start()
		
	def stop(self):
		self.main_thread.kill()
		return (self.pcap_path, self.http_file)