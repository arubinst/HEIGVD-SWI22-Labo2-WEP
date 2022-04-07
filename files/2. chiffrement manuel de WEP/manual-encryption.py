#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Alexandra Cerottini and Nicolas Ogi"
__copyright__   = "Copyright 2022, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "alexandra.cerottini@heig-vd.ch"
__status__	= "Prototype"

from scapy.all import *
import binascii
from scapy.layers.dot11 import RadioTap
from rc4 import RC4


# WEP key AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# plaintext to encrypt
data = b'Stephane est le pote de Squeezie en cachette'
# ICV calculated from data
icv = (binascii.crc32(data) % (1 << 32)).to_bytes(4, byteorder='little')
data_icv = data + icv

# IV chosen randomly
iv = b'\x01\x02\x03'
seed_rc4 = iv + key

# generate the keystream from RC4 algorithm
keystream = RC4(seed_rc4, streaming=False)
# XOR between the data_icv and the keystream to get the encrypted data
frame_body_icv = keystream.crypt(data_icv)

# open the arp.cap to copy it
arp = rdpcap('arp.cap')[0]
# replace the data in the frame with our ciphertext (we do not add the 4 last bytes because it is the ICV)
arp.wepdata = frame_body_icv[:-4]
arp.iv = iv
# replace the ICV in the frame with our ICV
arp.icv = struct.unpack('!L', frame_body_icv[-4:])[0]

# enable scapy to recalculate the length of the frame
arp[RadioTap].len = None
# generate the new cap file with our data
wrpcap('arp2.cap', arp, append=False)

print('Plaintext (str)     : ' + str(data))
print('Plaintext (hex)     : ' + str(data.hex()))
print('Ciphertext          : ' + str(frame_body_icv[:-4].hex()))
print('Plain icv (num)     : ' + str(struct.unpack('!L', icv)))
print('Encrypted icv (hex) : ' + frame_body_icv[-4:].hex())
