#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 07.04.2022
# Descriptif : Manually encrypt a wep message given the WEP key
# Entrée     : manual-encryption 
# Sources    : https://docs.python.org/2/library/binascii.html
#            : https://docs.python.org/2/library/struct.html

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.layers.dot11 import RadioTap

#Cle wep AA:AA:AA:AA:AA
key=b'\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Fichier de sortie
generated_arp = "output.cap"

# Message a chiffrer
data = "THISISLABOFSWITOENCRYPTWEPMESSAGE"

# Calcul de l'ICV
icv = binascii.crc32(data.encode()) & 0xffffffff

# Conversion en unsigned
uncrypted_icv = struct.pack('<L', icv)

# trame pour RC4
msg_rc4 = data.encode() + uncrypted_icv

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cipher_text=cipher.crypt(msg_rc4)

# recupération de l'ICV + format Long big endian
arp.icv = struct.unpack('!L', cipher_text[-4:])[0]

# le message sans icv
arp.wepdata = cipher_text[:-4]

# affichage
print ('Message : ' + data)
print ('Encrypted Message : ' + cipher_text[:-4].hex())
print ("icv : " + '{:x}'.format(icv)) 
print ("icv encrypted : " + cipher_text[-4:].hex()) 

# Reset du fichier cap
arp[RadioTap].len = None

# création pcap
wrpcap(generated_arp, arp)