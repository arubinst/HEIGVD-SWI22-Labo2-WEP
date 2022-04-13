#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Authors: Delphine Scherler & Wenes Limem
# Date: 14.04.2022
# Description: Manually encrypt a WEP message given the WEP key with fragmentation

import binascii
from scapy.all import *
from scapy.layers.dot11 import RadioTap
from files.rc4 import RC4


# WEP key AA:AA:AA:AA:AA
wep_key = b'\xaa\xaa\xaa\xaa\xaa'
data = [b'Nous sommes ', b'Delphine Scherler et ', b'Wenes Limem']
iv = b'\x05\x02\x04'

# Key for RC4 algorithm
key = iv + wep_key

# RC4 algorithm
keystream = RC4(key, streaming=False)

# Use given cap as template
arp = rdpcap('../files/arp.cap')[0]
# Update iv
arp.iv = iv

# Create frames
for i in range(0, len(data)):
    # Calculate ICV
    icv = (binascii.crc32(data[i]) % (1 << 32)).to_bytes(4, byteorder='little')
    # Append ICV to data
    data_icv = data[i] + icv

    # XOR keystream and data_icv
    encrypted_data = keystream.crypt(data_icv)
    # Update wepdata, without ICV
    arp.wepdata = encrypted_data[:-4]
    # Update ICV, convert it to Long
    arp.icv = struct.unpack('!L', encrypted_data[-4:])[0]
    # Rewrite length
    arp[RadioTap].len = None

    # Add SC field with frame number
    arp.SC = i
    # Add More Fragments field
    arp.FCfield.MF = 1
    # Last fragment, More Fragments is 0
    if i == len(data) - 1:
        arp.FCfield.MF = 0

    # Write frame in capture file
    wrpcap('encrypt_frag.cap', arp, append=True)