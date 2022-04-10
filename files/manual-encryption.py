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

#Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Fichier de sortie au format "pcap"
generated_arp = "output.cap"

# Message a chiffrer
data = "THISISLABOFSWITOENCRYPTWEPMESSAGE"

# Calcul de l'ICV et ajout au corps de la trame après les datas
icv = binascii.crc32(data.encode()) & 0xffffffff

# Conversion en unsigned de l'ICV
uncrypted_icv = struct.pack('<L', icv)

# Trame pour RC4 (composée des données + de l'ICV)
msg_rc4 = data.encode() + uncrypted_icv

# RC4 seed est composé de IV + clé
seed = arp.iv+key

# Chiffrement rc4
cipher = RC4(seed, streaming=False)
cipher_text=cipher.crypt(msg_rc4)

# Recupération de l'ICV + format Long big endian
arp.icv = struct.unpack('!L', cipher_text[-4:])[0]

# Le message sans l'ICV
arp.wepdata = cipher_text[:-4]

# Affichage
print ('Message : ' + data)
print ('Encrypted Message : ' + cipher_text[:-4].hex())
print ("icv : " + '{:x}'.format(icv)) 
print ("icv encrypted : " + cipher_text[-4:].hex()) 

# Reset du fichier cap
arp[RadioTap].len = None

# Création du fichier pcap
wrpcap(generated_arp, arp)