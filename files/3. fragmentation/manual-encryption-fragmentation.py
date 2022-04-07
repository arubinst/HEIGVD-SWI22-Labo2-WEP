#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually fragment a wep message given the WEP key"""

__author__ = "Alexandra Cerottini and Nicolas Ogi"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "alexandra.cerottini@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
import binascii
from scapy.layers.dot11 import RadioTap
from rc4 import RC4

# WEP key AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# fragments to encrypt
fragments = [b'Stephane est le ', b'pote de Squeezie ', b'en cachette']

# IV chosen randomly
iv = b'\x01\x02\x03'
seed_rc4 = iv + key

# generate the keystream from RC4 algorithm
keystream = RC4(seed_rc4, streaming=False)

# open the arp.cap to copy it
arp = rdpcap('arp.cap')[0]

arp.iv = iv
for i in range(0, len(fragments)):
    # ICV calculated from fragment
    icv = (binascii.crc32(fragments[i]) % (1 << 32)).to_bytes(4, byteorder='little')
    frag_icv = fragments[i] + icv
    # XOR between the frag_icv and the keystream to get the encrypted fragment
    frame_body_icv = keystream.crypt(frag_icv)
    # replace the data in the frame with our ciphertext (we do not add the 4 last bytes because it is the ICV)
    arp.wepdata = frame_body_icv[:-4]
    # replace the ICV in the frame with our ICV
    arp.icv = struct.unpack('!L', frame_body_icv[-4:])[0]
    # enable scapy to recalculate the length of the frame
    arp[RadioTap].len = None
    # counter of fragments
    arp.SC = i
    # set the More Fragments bit to 0 if it's the last fragment, 1 otherwise.
    arp.FCfield.MF = i < (len(fragments) - 1)
    # generate the new cap file with our data. If it's the first fragment, data are erased from the template, otherwise
    # the fragments are appended
    wrpcap('arp3.cap', arp, append=(i != 0))

    print(f'Plain fragment{i} (str)     : ' + str(fragments[i]))
    print(f'Plain fragment{i} (hex)     : ' + str(fragments[i].hex()))
    print(f'Encrypted fragment{i}       : ' + str(frame_body_icv[:-4].hex()))
    print('Plain icv (num)           : ' + str(struct.unpack('!L', icv)))
    print('Encrypted icv (hex)       : ' + frame_body_icv[-4:].hex() + '\n')
