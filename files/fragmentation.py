#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 14.04.2022
# Description : Send fragmented packet

import argparse

from scapy.all import *
import binascii
from rc4 import RC4
import zlib

# WEP key AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
textToSend = "testTestTest".encode()


def createFrame():
    tab = []
    LEN = 4
    for i in range(0, LEN):
        # Get the trame
        trame = rdpcap('arp.cap')[0]

        # rc4 seed is composded of IV + Key
        seed = trame.iv + key

        #Fragment number
        trame.SC = i

        trame[RadioTap].len = None

        #Compute ICV
        icvClear = binascii.crc32(textToSend).to_bytes(4, byteorder='little')

        # Encrypt with rc4
        cipher = RC4(seed, streaming=False)
        cipherText = cipher.crypt(textToSend + icvClear)
        trame.icv = struct.unpack('!L', cipherText[-4:])[0]

        # message without ICV
        trame.wepdata = cipherText[:-4]
        if i == (LEN - 1):
            trame.FCfield = trame.FCfield & 0xFB
        else:
            trame.FCfield = trame.FCfield | 0x04
        tab.append(trame)
    return tab


def sendFrame(tab):
    # Write trame into a Wireshark file
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
    wrpcap("trameFrag.pcapng", tab)
    #sendFrame(tab)

main()
