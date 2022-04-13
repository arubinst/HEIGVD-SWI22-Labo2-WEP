#!/usr/bin/env python
#-*- coding: utf-8 -*-

""" Manually encrypt a wep fragmented message given the WEP key"""

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

# Message à chiffrer repris du paquet donné en exemple puis coupé en trois.
# Notre but étant de reproduire le même paquet
cleartext1 = bytearray.fromhex('aaaa030000000806000108')
cleartext2 = bytearray.fromhex('00060400019027e4ea61f2c0')
cleartext3 = bytearray.fromhex('a80164000000000000c0a801c8')

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp1 = rdpcap('arp.cap')[0]
arp2 = rdpcap('arp.cap')[0]
arp3 = rdpcap('arp.cap')[0]

# Rc4 seed est composé de IV+clé
seed1 = arp1.iv + key
seed2 = arp2.iv + key
seed3 = arp3.iv + key

# Calcul de l'ICV
icv1 = binascii.crc32(cleartext2) & 0xffffffff
icv2 = binascii.crc32(cleartext3) & 0xffffffff
icv3 = binascii.crc32(cleartext1) & 0xffffffff

# Passage de l'ICV en bytes long little endian
icv3 = struct.pack('<L', icv3)
icv1 = struct.pack('<L', icv1)
icv2 = struct.pack('<L', icv2)

# essage + ICV
frame1 = cleartext1 + icv3
frame2 = cleartext2 + icv1
frame3 = cleartext3 + icv2

# Chiffrement des messages et l'ICVs
cipher1 = RC4(seed1, streaming=False)
cryptedText1 = cipher1.crypt(frame1) 

cipher2 = RC4(seed2, streaming=False)
cryptedText2 = cipher2.crypt(frame2) 

cipher3 = RC4(seed3, streaming=False)
ciphertext3 = cipher3.crypt(frame3)

# Séparation du ciphertext pour avoir l'ICV et le message
# Récupération de la partie ICV
icv_encrypted1=cryptedText1[-4:]
(icv_numerique1,)=struct.unpack('!L', icv_encrypted1)

icv_encrypted2=cryptedText2[-4:]
(icv_numerique2,)=struct.unpack('!L', icv_encrypted2)

icv_encrypted3=ciphertext3[-4:]
(icv_numerique3,)=struct.unpack('!L', icv_encrypted3)

# Récupération de la partie message
ciphertxt1 = cryptedText1[:-4] 
ciphertxt2 = cryptedText2[:-4] 
ciphertxt3 = ciphertext3[:-4] 

# Ajout du text chiffré dans la partie data du paquet
arp1.wepdata = ciphertxt1
arp2.wepdata = ciphertxt2
arp3.wepdata = ciphertxt3

# Ajout de l'ICV dans sa partie du paquet
arp1.icv = icv_numerique1
arp2.icv = icv_numerique2
arp3.icv = icv_numerique3

# Ajout du bit More fragment pour les trames 1 et 2
arp1.FCfield.MF = True
arp2.FCfield.MF = True

# Set du bit More fragment de la dernière trame à 0
arp3.FCfield.MF = False

# N° de fragment
arp1.SC += 1
arp2.SC += 2
arp3.SC += 3

# Mise a jour de la taille du paquet
arp3[RadioTap].len = None
arp1[RadioTap].len = None 
arp2[RadioTap].len = None

# Concaténation des trames
arp = []
arp.append(arp1)
arp.append(arp2)
arp.append(arp3)

# Ecriture de la nouvelle trame dans le fichier arp3.cap
wrpcap("arp3.cap", arp)
