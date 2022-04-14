#!/usr/bin/python3
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""
__author__      = "Pellissier David & Ruckstuhl Michael"

from scapy.all import *
import binascii
import argparse
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

    icv = binascii.crc32(msg).to_bytes(4, "little")

    ## data_to_encrypt = payload + ICV
    data_to_encrypt = msg + icv

    # rc4 seed est composé de IV+clé
    seed = pkt.iv + key

    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    ciphertext=cipher.crypt(data_to_encrypt)

    # affect ciphertext as new payload
    pkt.wepdata = ciphertext[:-4]
    encrypted_icv = ciphertext[-4:]
    pkt.icv = int.from_bytes(encrypted_icv, byteorder='big')

    pkt['RadioTap'].len = None # force Scapy to recalculate it

    return pkt


if __name__ == "__main__":

    # just parsing arguments
    parser = argparse.ArgumentParser(
        description="Manually encrypt WEP data",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("--data", help="Data to encrypt. If not defined, use decrypted data from arp.cap")

    args = parser.parse_args()

    #Cle wep AA:AA:AA:AA:AA'\x00\x00\x00'
    key= b'\xaa\xaa\xaa\xaa\xaa'
    arp = rdpcap("arp.cap")[0]

    if args.data:
        msg = bytes(args.data, "utf-8")
    else:
        print("Using reference_cap data")
        msg = decrypt(arp, key)
    
    #lecture de message clair

    arp = encrypt(msg, arp, key)

    # export
    wrpcap("arp_reencrypted.cap", arp)
    
    arp.show2()
    print("Exported cap file")