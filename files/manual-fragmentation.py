#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auteurs    : Dylan Canton & Christian Zaccaria
# Date       : 08.04.2022
# Descriptif : Manually encrypt a wep + fragment packet
# Entrée     : manual-fragmentation 
# Sources    : https://docs.python.org/2/library/binascii.html
#            : https://docs.python.org/2/library/struct.html

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.layers.dot11 import RadioTap

#Cle wep AA:AA:AA:AA:AA
key=b'\xaa\xaa\xaa\xaa\xaa'

# Fichier de sortie au format "pcap"
generated_arp = "outputfragmented.pcap"

# Message a chiffrer (le fragment doit faire 36 chars)
data_frag = "THISISAFRAGOFWEPMANUALFRAGMENTATION!"

# Longueur des datas
DATA_FRAG_LEN = len(data_frag)

# Nombre de fragments désirés
nb_frag = 4

# Multiplication du message à chiffer par le nombre de fragments totaux
data = data_frag * nb_frag

# Encryption des données
def encryption(key, data, arp):
    # Calcul de l'ICV
    icv = binascii.crc32(data.encode()) & 0xffffffff

    # Conversion en unsigned
    uncrypted_icv = struct.pack('<L', icv)

    # trame pour RC4
    msg_rc4 = data.encode() + uncrypted_icv

    # Rc4 seed est composé de IV+clé
    seed = arp.iv+key

    # Chiffrement rc4
    cipher = RC4(seed, streaming=False)
    cipher_text = cipher.crypt(msg_rc4)

    return cipher_text


# Création d'un packet
def create_packet(key, data):
    # Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]

    #Copie pour creation du paquet
    packet = arp

    # On récupère les données encrypté
    cipher_text = encryption(key, data, arp)

    # recupération de l'ICV + format Long big endian
    packet.icv = struct.unpack('!L', cipher_text[-4:])[0]

    # le message sans icv
    packet.wepdata = cipher_text[:-4]

    return packet

# Si le file existe, il le supprime
if os.path.isfile(generated_arp):
    os.remove(generated_arp)

# Compteur pour la numérotation des fragments 
i = 0

# On construit un paquet pour chaque fragment
while(nb_frag > 0):
    msg = data[:DATA_FRAG_LEN]
    packet = create_packet(key, msg)

    # Met le bit more fragments à 1 (sauf pour le dernier fragment)
    if (len(data) > DATA_FRAG_LEN):
        packet.FCfield |= 0x4

    # Numérote les fragments
    packet.SC = i
    i += 1

    # On enlève le début des données (traitées : OK)
    data = data[DATA_FRAG_LEN:]

    # On génère le pcap (si pas créé) avec le paquet fragmenté et on ajoute à la suite chaque fragment
    wrpcap(generated_arp, packet, append=True)

    # Décrémente nb_frag pour passer au frag suivant
    nb_frag -= 1
