#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" 2. Chiffrement manuel de WEP : chiffrement d'un message avec WEP"""

__author__      = "Wonjamouna Rosy-Laure, Tevaearai RÃ©becca"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from os import urandom
from scapy.all import *
import binascii
from rc4 import RC4
from Crypto import Random


# writing 
def write(pkt, filename) :
    wrpcap(filename, pkt, append=True)

arp = rdpcap("arp.cap")[0]

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# random iv
iv = Random.get_random_bytes(3)

# Données à chiffrer
data = b'1234567890145'

# Lecture du message déchiffré
arp = rdpcap('arp.cap')[0]


# rc4 seed est composé de IV+clé
seed = iv + key

# Calcul du CRC sur les données
icv= binascii.crc32(data)


# Chiffrement avec RC4
cipher = RC4(seed, streaming=False)
encrypted_frame= cipher.crypt(data + icv.to_bytes(4, byteorder='little'))

arp.iv = iv
arp.icv = int.from_bytes(encrypted_frame[-4:], byteorder='big')
arp.wepdata = encrypted_frame[:-4]
arp["RadioTap"].len = None



write(arp, "test.cap")


