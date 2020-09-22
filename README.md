<h1 align="center">mitm.py</h1>

<p align="center">Tool developed in Python 3 using Scapy for <b>MITM</b > attacks</p>

## :open_file_folder: Project Structure

```
mitm.py
├── include
|   ├── arppoison.py
|   ├── ftp_sniff.py
|   └── http_sniff.py
├── requirements.txt
└── mitm.py
```

### Attacks
- [x] ARP Poisoning
- [x] FTP Sniffing
- [x] HTTP Sniffing
- [ ] DNS Spoofing
- [x] Captive Portal

## Installation

First, install python 3:

- On Debian and Ubuntu
```sh
apt-get install python3 python3-dev python3-pip
``` 

Now you're ready to install the tool!

- Clone the repo:
```sh
git clone https://github.com/ReddyyZ/mitm.py
```

- Cd into the directory and install the requirements:
```sh
pip3 install -r requirements.txt
```

- Happy hacking!
```sh
python3 mitm.py --help
```