#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Adrien Peguiron & Nicolas Viotti"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "adrien.peguiron@heig-vd.ch, nicolas.viotti@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
#IV de 24 bits pour RC4
iv = b'\x0c\x4d\x5c'

# Récupération d'une trame utilisée comme template
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = iv+key

# texte clair, doit être en hexadécimal
message_clair=b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
# création de l'icv
icv = binascii.crc32(message_clair)
# concaténation du message clair et de l'icv pour chiffrer en RC4
message_clair+=icv.to_bytes(4, byteorder='little')

# chiffrement RC4
cipher = RC4(seed, streaming=False)
ciphertext=cipher.crypt(message_clair)

# On remplace le texte par le notre
arp.wepdata = ciphertext[:-4]
# On remplace l'ICV par le notre
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
# On remplace l'IV par le notre
arp.iv = iv

# Ecriture de la trame dans un nouveau fichier
wrpcap('arp-encryption.cap', arp, append=False)
