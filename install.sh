#!/bin/bash
apt-get install python3 python3-dev python3-pip
python3 -m pip install -r requirements.txt

mkdir -p /usr/share/mitm.py
mkdir -p /usr/share/mitm.py/files
mkdir -p /usr/share/mitm.py/config

cp -r * /usr/share/mitm.py

echo "mitm.py installed!"
