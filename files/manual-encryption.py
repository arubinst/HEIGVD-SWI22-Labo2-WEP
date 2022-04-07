#!/usr/bin/env python
# -*- coding: utf-8 -*-


# Author : Quentin Le Ray, Ryan Sauge
# Date : 07.04.2022
# Description : Manually encrypt a wep message given the WEP key


from scapy.all import *
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
textToSend = b"Coucou"


# Recup trame
trame = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = trame.iv + key

icvClear = long_to_bytes(binascii.crc32(textToSend))

# Chiffrement rc4
cipher = RC4(seed, streaming=False)
cipherText = cipher.crypt(textToSend + icvClear)

trame.icv = bytes_to_long(cipherText[-4:])

# le message sans le ICV
trame.wepdata = cipherText[:-4]

# Write trame into a Wireshark file
wrpcap("trameToSend.pcapng", trame)

exit()

############################################ To Remove #####################################################

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv + key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières
# de faire ceci...
icv_encrypted = '{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted = arp.wepdata + bytes.fromhex(icv_encrypted)

# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cleartext = cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair = cleartext[-4:]
icv_enclair = icv_enclair
icv_numerique = struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair = cleartext[:-4]

print('Text: ' + text_enclair.hex())
print('icv:  ' + icv_enclair.hex())
print('icv(num): ' + str(icv_numerique))
