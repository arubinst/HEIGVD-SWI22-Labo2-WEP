#!/usr/bin/env python
#-*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Godi Matthieu, Issolah Maude"
__copyright__   = "Copyright 2022, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key=b'\xaa\xaa\xaa\xaa\xaa'

# Message à chiffrer repris du paquet donné en exemple.
# Notre but étant de reproduire le même paquet
cleartext = bytearray.fromhex('aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8')

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0] 

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# Calcul de l'ICV 
icv = binascii.crc32(cleartext) & 0xffffffff

# Passage de l'ICV en bytes long little endian
icv = struct.pack('<L', icv)

# Message + ICV
frame = cleartext + icv

# Chiffrement du message et de l'ICV
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(frame)  

# Séparation du ciphertext pour avoir l'ICV et le message
# Récupération de la partie ICV
icv_encrypted=ciphertext[-4:]
(icv_numerique,)=struct.unpack('!L', icv_encrypted)

# Récupération de la partie message
ciphertxt=ciphertext[:-4] 

# Ajout du text chiffré dans la partie data du paquet
arp.wepdata = ciphertxt

# Ajout de l'ICV dans sa partie du paquet
arp.icv = icv_numerique

# Mise a jour de la taille du paquet
arp[RadioTap].len = None 

# Ecriture de la nouvelle trame dans le fichier arp2.cap
wrpcap("arp2.cap", arp)
