[Livrables](#livrables)

[Échéance](#échéance)

[Travail à réaliser](#travail-à-réaliser)

# Sécurité des réseaux sans fil

## Laboratoire 802.11 Sécurité WEP

__A faire en équipes de deux personnes__

### Pour cette partie pratique, vous devez être capable de :

* Déchiffrer manuellement des trames WEP utilisant Python et Scapy
* Chiffrer manuellement des trames WEP utilisant Python et Scapy
* Forger des fragments protégés avec WEP afin d’obtenir une keystream de longueur plus grande que 8 octets


Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). 


## Travail à réaliser

### 1. Déchiffrement manuel de WEP

Dans cette partie, vous allez récupérer le script Python [manual-decryption.py](files/manual-decryption.py). Il vous faudra également le fichier de capture [arp.cap](files/arp.cap) contenant un message arp chiffré avec WEP et la librairie [rc4.py](files/rc4.py) pour générer les keystreams indispensables pour chiffrer/déchiffrer WEP. Tous les fichiers doivent être copiés dans le même répertoire local sur vos machines.

- Ouvrir le fichier de capture [arp.cap](files/arp.cap) avec Wireshark
  
- Utiliser Wireshark pour déchiffrer la capture. Pour cela, il faut configurer dans Wireshark la clé de chiffrement/déchiffrement WEP (Dans Wireshark : Preferences&rarr;Protocols&rarr;IEEE 802.11&rarr;Decryption Keys). Il faut également activer le déchiffrement dans la fenêtre IEEE 802.11 (« Enable decryption »). Vous trouverez la clé dans le script Python [manual-decryption.py](files/manual-decryption.py).
  
- Exécuter le script avec `python manual-decryption.py`
  
- Comparer la sortie du script avec la capture text déchiffrée par Wireshark
  
- Analyser le fonctionnement du script

#### Manipulations

Voici la capture Wireshark:

![](images/1_0.png)

Output du script `manual-decryption.py`:

![](images/1_1.png)

On peut constater que la trame Wireshark, c'est une trame ARP. Nous voyons que son contenu est bien déchiffré. Au niveau de la valeur de l'ICV entre le script et Wireshark, nous constatons que leur valeur n'est pas pareille. Nous pouvons expliquer cela avec le fait que l'ICV dans le script est déchiffré alors que sur Wireshark sa valeur est chiffré.

> Fonctionnement du script

Le script va déchiffrer manuellement un message WEP à l'aide d'une clé WEP donnée. Il fonctionne précisément de la manière suivante:

- Premièrement  il va lire la capture `.pcap` avec des trames chiffrées. La méthode retourne un tableau avec tous les paquets.
- On va calculer la `seed` RC4 à l'aide de l'IV et de la clé
- On récupère l'ICV chiffré
- On récupère le message chiffré (avec l'ICV inclu)
- Finalement, on déchiffre avec la `seed` RC4 le message ainsi que l'ICV

### 2. Chiffrement manuel de WEP

Utilisant le script [manual-decryption.py](files/manual-decryption.py) comme guide, créer un nouveau script `manual-encryption.py` capable de chiffrer un message, l’enregistrer dans un fichier pcap et l’envoyer.
Vous devrez donc créer votre message, calculer le contrôle d’intégrité (ICV), et les chiffrer (voir slides du cours pour les détails).


### Quelques éléments à considérer :

- Vous pouvez utiliser la même trame fournie comme « template » pour votre trame forgée (conseillé). Il faudra mettre à jour le champ de données qui transporte le message (`wepdata`) et le contrôle d’intégrite (`icv`).
- Le champ `wepdata` peut accepter des données en format text mais il est fortement conseillé de passer des bytes afin d'éviter les soucis de conversions.
- Le champ `icv` accepte des données en format « long ».
- Vous pouvez vous guider à partir du script fourni pour les différentes conversions de formats qui pourraient être nécessaires.
- Vous pouvez exporter votre nouvelle trame en format pcap utilisant Scapy et ensuite, l’importer dans Wireshark. Si Wireshark est capable de déchiffrer votre trame forgée, elle est correcte !

#### Fonctionnement du script

- En premier lieu on déclare 3 variables, une clé de 40 bits, un iv de 24 bits ainsi qu'un message arbitraire d'une certaine longueur (nous avons récupéré le message du script  `manual-decryption.py` et nous avons uniquement modifié le dernier byte)
- On lit toutes les trames de la capture `pcap` chiffrée
- On calcule la seed RC4 à l'aide de la clé et de l'IV
- On calcule le ICV pour l'intégrité avec la méthode `crc32` de la libraire `zlib`
- Finalement, on chiffre toutes les données et on les écrit dans un fichier `.pcap`

#### Résultat

On peut voir ci-dessous que la trame ARP est correctement déchiffrée avec la clé. En comparaison avec la capture Wireshark dans la partie 1, nous voyons que dans le message d'information l'adresse IP précisée `192.168.1.200` a changé en `192.168.1.255` car nous avons modifié les derniers bytes. 

![](images/2_0.png)


### 3. Fragmentation

Dans cette partie, vous allez enrichir votre script développé dans la partie précédente pour chiffrer 3 fragments.

### Quelques éléments à considérer :

- Chaque fragment est numéroté. La première trame d’une suite de fragments a toujours le numéro de fragment à 0. Une trame entière (sans fragmentation) comporte aussi le numéro de fragment égal à 0
- Pour incrémenter le compteur de fragments, vous pouvez utiliser le champ « SC » de la trame. Par exemple : `trame.SC += 1`
- Tous les fragments sauf le dernier ont le bit `more fragments` à 1, pour indiquer qu’un nouveau fragment va être reçu
- Le champ qui contient le bit « more fragments » est disponible en Scapy dans le champ `FCfield`. Il faudra donc manipuler ce champ pour vos fragments. Ce même champ est visible dans Wireshark dans IEEE 802.11 Data &rarr; Frame Control Field &rarr; Flags
- Pour vérifier que cette partie fonctionne, vous pouvez importer vos fragments dans Wireshark, qui doit être capable de les recomposer
- Pour un test encore plus intéressant (optionnel), vous pouvez utiliser un AP (disponible sur demande) et envoyer vos fragments. Pour que l’AP accepte vous données injectées, il faudra faire une « fake authentication » que vous pouvez faire avec `aireplay-ng`
- Si l’AP accepte vos fragments, il les recomposera et les retransmettra en une seule trame non-fragmentée !

#### Résultat

Sur la capture suivante, on peut voir que notre première trame est bel et bien un fragment (A), qu'il est le premier (B), que d'autres fragments vont suivre (C) et que ce dernier était bien chiffré avec WEP (D). On remarque notamment que l'on peut retrouver le paquet reconstitué au dernier fragment (E).

![](images/3_0.png)

Sur la capture suivante, on peut voir que notre dernière trame est bel et bien la recomposition de tous les fragments (A), que c'est le troisième fragment (B), qu'il n'y a plus de fragments après celui-ci (C) et que ce dernier était bien chiffré avec WEP (D). On remarque également le texte maintenant déchiffré et en clair (E)

![](images/3_1.png)

## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

-	Script de chiffrement WEP **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant la trame chiffrée
  - Capture d’écran de votre trame importée et déchiffré par Wireshark
-	Script de fragmentation **abondamment commenté/documenté**
  - Fichier pcap généré par votre script contenant les fragments
  - Capture d’écran de vos trames importées et déchiffrés par Wireshark 

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 14 avril 2022 à 23h59
