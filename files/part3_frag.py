#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 09.04.2022
# Description : Send fragmented packet
import argparse

from scapy.all import *
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long
from rc4 import RC4
import zlib

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
textToSend = b"Coucou"


# icvClear = long_to_bytes(binascii.crc32(textToSend))
# icvClear = (binascii.crc32(textToSend)).to_bytes(4, byteorder='big')
def createFrame():
    tab = []
    for i in range(0, 3):
        # Recup trame
        trame = rdpcap('arp.cap')[0]

        # rc4 seed est composé de IV+clé
        seed = trame.iv + key
        print("IV", hex(bytes_to_long(trame.iv)))
        trame.SC = i
        icvClear = (zlib.crc32(textToSend)).to_bytes(4, byteorder='little')

        # Chiffrement rc4
        cipher = RC4(seed, streaming=False)
        cipherText = cipher.crypt(textToSend + icvClear)

        # trame.icv = bytes_to_long(cipherText[-4:])
        print("trame icv", trame.icv)
        trame.icv = int.from_bytes(cipherText[-4:], byteorder='little')
        print("trame icv", trame.icv)

        # le message sans le ICV
        # trame.wepdata = cipherText[:-4]
        trame.wepdata = cipherText[:-4]
        if i == 2:
            trame.FCfield = trame.FCfield & 0xFB
        else:
            trame.FCfield = trame.FCfield | 0x04
        tab.append(trame)
        # Write trame into a Wireshark file
    return tab


def sendFrame(tab):
    wrpcap("trameFrag.pcapng", tab)
    # Passing arguments
    parser = argparse.ArgumentParser(prog="Send trame",
                                     usage="%(prog)s -i wlan0mon",
                                     description="Send trame",
                                     allow_abbrev=True)
    parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of")
    args = parser.parse_args()

    sendp(tab, iface=args.Interface)


def main():
    tab = createFrame()
    sendFrame(tab)


main()
