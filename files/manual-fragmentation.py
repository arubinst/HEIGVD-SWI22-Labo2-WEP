#!/usr/bin/env python
# -*- coding: utf-8 -*-
# auteurs: Jean-Luc Blanc & Noémie Plancherel

from scapy.all import *
from rc4 import RC4
import zlib

# Encryption
def encryption(key, data, arp):
	# ICV
	icv = zlib.crc32(data.encode()).to_bytes(4, byteorder='little')
	
	msg = data.encode() + icv
	
	seed = arp.iv + key
	
	rc4 = RC4(seed, streaming=False)
	ciphertext = rc4.crypt(msg)
	
	return ciphertext
	

def create_packet(key, data):
	arp = rdpcap('arp.cap')[0]
	packet = arp
	ciphertext = encryption(key, data, arp)
	
	packet.icv = struct.unpack('!L', ciphertext[-4:])[0]
	packet.wepdata = ciphertext[:-4]
	packet.iv = arp.iv
	
	packet[RadioTap].len = None
	
	
	return packet
	
	
# -------------------------------------------------------------------------

# Output file for packets
capture = "fragmented_packets.pcap"

# Fragment (36 chars)
fragment = "FRAGMENTATIONPACKETWEPAAAAAAAAAAAAA!"
length = len(fragment)
	
# WEP Key
key=b'\xaa\xaa\xaa\xaa\xaa'

# number of fragments
nbr_frag = 3
# DATA
data = fragment * nbr_frag

# if the file exists we delete it
if os.path.isfile(capture):
	os.remove(capture)

# fragment counter
i = 0

# We iterate on the number of fragments and we create a packet for each of them
while(nbr_frag > 0):
	msg = data[:length]
	packet = create_packet(key, msg)
	
	# We put the "more_fragment" bit at 1 but the last fragment
	if (len(data) > length):
		packet.FCfield |= 0x4
		
	# Numeroting the fragments
	packet.SC = i
	i += 1
	
	# we remove the early datas
	data = data[length:]
	
	# We create a pcap with the fragmented packet
	wrpcap(capture, packet, append=True)
	
	# We decrease the amount of fragments
	nbr_frag -= 1
