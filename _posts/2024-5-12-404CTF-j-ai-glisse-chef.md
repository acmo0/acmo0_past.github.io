---
layout: post
title: J'ai glissé chef !
categories: Write-up 404CTF 2024 crypto hard
---
![](images/j_ai_glisse_chef_screenshot.png)

# Informations générales
Nous avons affaire à un chiffrement par bloc, suivant un [schéma de Feistel](https://fr.wikipedia.org/wiki/R%C3%A9seau_de_Feistel) avec quelques détails assez étrange : il y a deux clés qui se répètent en alternant suivant le round et un nombre de round assez grand (96 rounds). Chaque clé fait 32 bits, une clé peut se bruteforcer mais les deux clés ne peuvent pas de bruteforcer. Il est à noter qu'aucun bruteforce des clés n'est nécessaire pour résoudre ce challenge.

# Résolution
Il est à noter que le script entier pour la résolution de ce challenge est disponible sur [ce github](https://github.com/acmo0/write-up/).

Cet algorithme est vulnérable à une [Slide Attack](https://en.wikipedia.org/wiki/Slide_attack) particulière. Une attaque par cryptanalyse différentielle ou linéaire semble compliquée ici justement à cause du nombre important de rounds. L'idée est de faire une attaque `slide with a twist` comme décrite dans [cet article](https://www.iacr.org/archive/eurocrypt2000/1807/18070595-new.pdf). Une fois la première clé récupérée, on peut suivre le reste de l'article (dont l'explication est assez vague) pour récupérer la seconde clé. Sinon, on peut "shifter" notre algoritme de chiffrement puis réitérer la même attaque, ce qui est plus rapide car toutes les fonctions sont déjà implémentées pour récupérer la première clé !

## Première clé
Pour notre slide attack, on doit générer beaucoup de textes à chiffrer / déchiffrer par notre oracle de chiffrement en espérant tomber sur une paire de clairs/chiffrés qui satisfasse certaines conditions particulière. En utilisant le paradoxe des anniversaires, on estime qu'il faut environ 2^16 clairs et 2^16 chiffrés pour récupérer la première clé. Voici comment les clairs/chiffrés sont générés (c.f article) : 
```python
def get_pool():
	pool1 = []									# act as plaintexts
	r = os.urandom(4)
	for i in range(2**16):
		print(round(i/2**16*100,2),end="\r")
		l = os.urandom(4)
		pool1.append(l+r)
	pool2 = []									# act as ciphertexts
	for i in range(2**16):
		print(round(i/2**16*100,2),end="\r")
		l = os.urandom(4)
		pool2.append(l+r)
	return pool1,pool2
```

Ensuite, on demande le chiffrement de la première pool et le déchiffrement de la deuxième pool par l'oracle mis à disposition.
L'idée est ensuite de trouver une paire qui satisfasse certaines conditions décrites dans l'article, une fois une telle paire trouvée, la déduction de la première clé est immédiate.

Cette méthode permet donc, pour un réseau de Feistel quelconque vulnérable à une slide attaque de retrouver la première clé. Afin de réutiliser ce qui a déjà été codé, il serait utile de se ramener exactement au même problème que précédement mais en changeant l'alternance des clés de chiffrement utilisées comme décrit dans la figure suivante :

![shiffted_cipher](images/diag1.png)

Pour cela, on met en place le système suivant :
![shiffter_cipher2](images/diag2.png)

Cela nous permet d'avoir exactement le réseau de Feistel désiré pour ré-itérer la même attaque déjà implémentée pour obtenir la seconde clé. Après avoir "entouré" notre oracle par un déchiffrement d'un round avec clé 1 avant et un chiffrement d'un round avec la clé 1 après, il suffit de recommencer et on obtient la seconde clé.