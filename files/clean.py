#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 07.04.2022
# Description : Manually encrypt a wep message given the WEP key
from scapy.all import *
import binascii
from rc4 import RC4

# WEP key AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
textToSend = "testTestTest".encode()

# Get the trame
trame = rdpcap('arp.cap')[0]
trame[RadioTap].len = None


# rc4 seed is composed of IV+clé
seed = trame.iv + key
icvClear = binascii.crc32(textToSend).to_bytes(4, byteorder='little')

# Encrypt with rc4
cipher = RC4(seed, streaming=False)
cipherText = cipher.crypt(textToSend + icvClear)
print(cipherText)
trame.icv = struct.unpack('!L', cipherText[-4:])[0]

# message without ICV
trame.wepdata = cipherText[:-4]

# Write trame into a Wireshark file
wrpcap("result.pcapng", trame)