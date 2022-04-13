#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors: Delphine Scherler & Wenes Limem
# Date: 14.04.2022
# Description: Manually encrypt a WEP message given the WEP key

import binascii
from scapy.all import *
from scapy.layers.dot11 import RadioTap
from files.rc4 import RC4


# Wep key AA:AA:AA:AA:AA
wep_key = b'\xaa\xaa\xaa\xaa\xaa'
data = b'Nous sommes Delphine Scherler et Wenes Limem'
iv = b'\x05\x02\x04'

# Key for RC4 algorithm
key = iv + wep_key

# RC4 algorithm
keystream = RC4(key, streaming=False)

# Calculate ICV
icv = (binascii.crc32(data) % (1 << 32)).to_bytes(4, byteorder='little')
# Append ICV to data
data_icv = data + icv

# XOR keystream and data_icv
encrypted_data = keystream.crypt(data_icv)


# Function to generate pcap file
def generate_pcap():
    # Use given cap as template
    arp = rdpcap('../files/arp.cap')[0]
    # Update wepdata, without ICV
    arp.wepdata = encrypted_data[:-4]
    arp.iv = iv
    # Update ICV, convert it to Long
    arp.icv = struct.unpack('!L', encrypted_data[-4:])[0]
    # Rewrite length
    arp[RadioTap].len = None
    # Write frame in capture file
    wrpcap('encrypt.cap', arp, append=False)


if __name__ == '__main__':
    generate_pcap()