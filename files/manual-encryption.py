#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 14.04.2022
# Description : Manually encrypt a wep message given the WEP key
import argparse

from scapy.all import *
import binascii

from rc4 import RC4


def createFrame(textToSend, key):
    # Get the trame
    trame = rdpcap('arp.cap')[0]

    # Ask scapy to compute the data length
    trame[RadioTap].len = None

    # rc4 seed is composed of IV+clé
    seed = trame.iv + key

    # compute crc32
    icvClear = binascii.crc32(textToSend).to_bytes(4, byteorder='little')

    # Encrypt with rc4
    cipher = RC4(seed, streaming=False)
    cipherText = cipher.crypt(textToSend + icvClear)

    # Put icv in the field of the trame
    trame.icv = struct.unpack('!L', cipherText[-4:])[0]

    # Put message without ICV into wepdata
    trame.wepdata = cipherText[:-4]

    # Write trame into a Wireshark file
    wrpcap("encryptedFrame.pcapng", trame)

    return trame


def main():
    # Passing arguments
    parser = argparse.ArgumentParser(prog="Send trame",
                                     usage="%(prog)s -i wlan0mon",
                                     description="Send trame",
                                     allow_abbrev=True)
    parser.add_argument("-i", "--Interface", required=True,
                        help="The interface that you want to send packets out of")
    args = parser.parse_args()
    textToSend = "CoucouCoucou".encode()
    # WEP key AA:AA:AA:AA:AA
    key = b'\xaa\xaa\xaa\xaa\xaa'

    # Create frame
    frame = createFrame(textToSend, key)

    # Send frame
    sendp(frame, iface=args.Interface)

main()
