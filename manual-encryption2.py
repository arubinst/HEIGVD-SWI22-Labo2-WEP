#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Wonjamouna Rosy-Laure, Tevaearai RÃ©becca"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from os import urandom
from scapy.all import *
import binascii
from rc4 import RC4

# writing 
def write(pkt, filename) :
    wrpcap(filename, pkt, append=True)

arp = rdpcap("arp.cap")[0]

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# random iv
iv = b'\x08\x87\xc5'

# Données à chiffrer
#data = b'123456789'

# Lecture du message déchiffré
arp = rdpcap('arp.cap')[0]


# rc4 seed est composé de IV+clé
seed = iv + key

arp.SC = -1 # On veut que le numéro du 1e fragment soit égal à 0

for x in range(0, 3): 
# Données à chiffrer pour nos 3 fragments
    if x == 0 :
        data = b'123456789'
    if x == 1 :
        data = b'abcdefghi'
    if x == 2 :
        data = b'ABCDEFGHI'
    # Calcul du CRC sur les données
    icv= binascii.crc32(data)

    # Chiffrement avec RC4
    cipher = RC4(seed, streaming=False)
    encrypted_frame= cipher.crypt(data + icv.to_bytes(4, byteorder='little'))

    arp.iv = iv
    arp.icv = int.from_bytes(encrypted_frame[-4:], byteorder='big')
    arp.wepdata = encrypted_frame[:-4]
    arp["RadioTap"].len = None

    arp.SC +=1 # On augmente le compteur de fragment
    arp.FCfield.MF = 1 # Le bit more fragment est à 1
    if x == 2 :
        arp.FCfield.MF = 0 # On veut que le dernier fragment est le bit more fragment à 0

    write(arp, "test2.cap")
