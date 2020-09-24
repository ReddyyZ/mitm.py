<h1 align="center">mitm.py</h1>

<p align="center">Tool developed in Python 3 using Scapy for <b>MITM</b > attacks</p>

<p align="center">
    <a href="#open_file_folder-Project-Structure">Project Structure</a> | 
    <a href="#gear-Installation">Installation</a> | 
    <a href="#gear-Configuring">Configuring</a> | 
    <a href="#open_book-Examples">Examples</a>
</p>

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
- [x] Captive Portal

## :gear: Installation

To learn how to install the script, see the wiki [Installation](https://github.com/ReddyyZ/mitm.py/wiki/Installation)

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
python3 mitm.py --arp --dns --gateway 192.168.1.1 --targets 192.168.1.106/192.168.1.104
```
> Remember to change the `config/hosts.json` file

- Sniffing all http requests
```sh
python3 mitm.py --http -v
```
> All requests will be saved at `files` directory

- Sniffing all FTP credentials
```sh
python3 mitm.py --ftp -v
```
> All credentials will be saved at `files` directory

- Enable Captive Portal
```sh
python3 mitm.py --arp --dns --captive --gateway 192.168.1.1 --targets 192.168.1.106
```
> Redirects all requests to your captive portal

<h2 align="center">&lt;/&gt; by <a href="https://github.com/ReddyyZ">ReddyyZ</a></h2>