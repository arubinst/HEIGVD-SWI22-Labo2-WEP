#!/usr/bin/env python
# -*- coding: utf-8 -*-
# auteurs: Jean-Luc Blanc & Noémie Plancherel

""" Manually encrypts a wep message given the WEP key"""

from scapy.all import *
import binascii
from rc4 import RC4
import zlib

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
# IV de 24 bits
iv = b'\x00\x00\x00'
# Message a chiffre, nous recuperons le message du script manual-decryption et on modifie le dernier byte
data = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xff'

#lecture de message chiffré
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = iv+key

# calcul du crc
icv = zlib.crc32(data).to_bytes(4, byteorder='little')

# chiffrement rc4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(data + icv)

# Payload
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = iv

# Writing package to .pcap file
wrpcap('step2.pcap', arp)
