from scapy.all import *
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
from multiprocessing import Process
import logging, netifaces, subprocess, signal

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

class Captive(object):
    x = random.randint(1000,9999)
    def __init__(self, server_ip="", serve_dir="/var/www/html", log_file="files/{x}-captive.log",verbose=False,interface="eth0"):
        self.log_file    = log_file
        self.main_thread = None
        self.local_ip    = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

        self.p         = None
        self.server_ip = server_ip
        self.serve_dir = serve_dir

        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{magenta}*{reset}]")
        logging.basicConfig(format=f"%(levelname)s %(message)s", level=logging.DEBUG if verbose else logging.INFO)

    def serve(self):
        self.p = subprocess.Popen(f"php -S {self.local_ip}:80 -t {self.serve_dir}".split(" "),stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)

    def start(self):
        if not self.server_ip:
            self.main_thread = Process(target=self.serve)
            self.main_thread.start()
            logging.debug("Captive: PHP server started")
        logging.debug("Captive: Captive Portal started!")
        
        return self.server_ip if self.server_ip else self.local_ip

    def stop(self):
        if not self.server_ip:
            self.p.send_signal(signal.CTRL_C_EVENT)
            self.p.kill()
            self.main_thread.kill()
            logging.debug("Captive: PHP server stopped")

if __name__ == "__main__":
    captive = Captive(verbose=True)
    captive.start()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        captive.stop()