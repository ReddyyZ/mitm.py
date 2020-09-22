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
- [x] DNS Spoofing
- [ ] Captive Portal

## :gear: Installation

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
cd mitm.py && pip3 install -r requirements.txt
```

- Happy hacking!
```sh
python3 mitm.py --help
```

## :gear: Configuring

To configure the hosts for DNS Spoofing attacks, you need to change the [config/hosts.json](config/hosts.json), following these instructions:

```json
{
    "kali.ada.": "192.168.1.105",
    "test.root.": "192.168.1.105"
}
```

Set the key name as the host, and the value as the IP to be redirected.
And remember to add the '.' at the end.

## :open_book: Examples

- Poisoning the ARP and executing DNS Spoofing
```sh
python mitm.py --arp --dns --gateway 192.168.1.1 --targets 192.168.1.106/192.168.1.104
```
> Remember to change the `config/hosts.json` file