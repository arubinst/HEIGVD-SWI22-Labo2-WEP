#!/usr/bin/python3
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import argparse
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'


# just parsing arguments
parser = argparse.ArgumentParser(
    description="Manually encrypt WEP data",
    epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
parser.add_argument("cap", help="CAP file with encrypted WEP data")

args = parser.parse_args()


#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
#arp = rdpcap('arp_reencrypted.cap')[0]  
arp = rdpcap(args.cap)[0]  

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+bytes.fromhex(icv_encrypted)

# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cleartext=cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair=cleartext[-4:]
icv_enclair = icv_enclair
icv_numerique=struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair=cleartext[:-4]

print ('Text: ' + text_enclair.hex())
print ('icv:  ' + icv_enclair.hex())
print ('icv(num): ' + str(icv_numerique))
