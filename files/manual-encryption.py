#!/usr/bin/python3
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""
__author__      = "Pellissier David & Ruckstuhl Michael"

from scapy.all import *
import binascii
from rc4 import RC4

def decrypt(pkt, key):

    # rc4 seed est composé de IV+clé
    seed = pkt.iv+key

    # recuperation de icv dans le message (pkt.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
    icv_encrypted='{:x}'.format(pkt.icv)

    # text chiffré y-compris l'icv
    message_encrypted=pkt.wepdata+bytes.fromhex(icv_encrypted)

    # déchiffrement rc4
    cipher = RC4(seed, streaming=False)
    cleartext=cipher.crypt(message_encrypted)

    # le ICV est les derniers 4 octets - je le passe en format Long big endian
    icv_enclair=cleartext[-4:]
    icv_enclair = icv_enclair
    icv_numerique=struct.unpack('!L', icv_enclair)

    # le message sans le ICV
    text_enclair=cleartext[:-4]
    return text_enclair

def encrypt(msg, pkt, key):

    # ICV = CRC23(payload)
    icv = binascii.crc32(msg)

    ## data_to_encrypt = payload + ICV
    data_to_encrypt = msg + icv.to_bytes(4, "big")

    # rc4 seed est composé de IV+clé
    seed = pkt.iv+key # on peut changer l'IV

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    ciphertext=cipher.crypt(data_to_encrypt)

    # affect ciphertext as new payload
    pkt.wepdata = ciphertext
    pkt.icv = icv # transformation en format Long big endian

    return pkt


if __name__ == "__main__":

    #Cle wep AA:AA:AA:AA:AA
    key= b'\xaa\xaa\xaa\xaa\xaa'

    arp = rdpcap('arp.cap')[0]
    #lecture de message clair
    msg = decrypt(arp, key)

    

    arp = encrypt(msg, arp, key)

    # export
    #print(arp.show())
    wrpcap("arp_reencrypted.cap", arp, append=True)
    
    print("Exported cap file")