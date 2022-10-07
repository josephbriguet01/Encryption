Copyright © JasonPercus Systems, Inc - All Rights Reserved
# **Introduction**

Cette librairie apporte une multitude de fonctions utiles permettant de chiffer/déchiffer un texte, un tableau de byte ou un flux. À savoir qu'elle possède une dépendance vers le projet :

- [Util-1.15.1](https://github.com/josephbriguet01/Util) (attention ce projet possède lui aussi des dépendances)

# **Dé/Chiffrement**
La librairie permet entre-autre de dé/chiffrer des textes/tableau de bytes.

## 1. Base

Cette classe n'a pas de réelle fonction pour le développeur lambda. Elle est la classe mère de la classe ```Base64```. Mais elle peut servir pour créer d'autre base comme par exemple la base 32. Exemple, pour créer une base 32:
```java
Base base32 = new Base(32);
```

## 2. Base64

Cette classe est très utilisée pour convertir un tableau de bytes en texte visible par l'utilisateur et vice-versa. Voici un exemple de son utilisation:
```java
//Création d'un objet Base64
Base64 base64 = new Base64();

//Il s'agit de mon texte à chiffrer en base64
byte[] array = "Mon texte converti en bytes".getBytes();

//Chiffrement & déchiffrement
String encrypted = base64.toString(array);
byte[] decrypted = base64.toBytes(encrypted);

//Affichages des résultats
System.out.println("Encrypted: " + encrypted);
System.out.println("Decrypted: " + new String(decrypted));
```
Nous obtenons ce résultat
```
Encrypted: TW9uIHRleHRlIGNvbnZlcnRpIGVuIGJ5dGVz
Decrypted: Mon texte converti en bytes
```
Il existe plusieurs types de chiffrement Base64:
- ```BASE```: Lorsque l'on souhaite dé/chiffrer de manière classique (sur une ligne et sans espace)
- ```WITH_LINE_BREAK```: Lorsque l'on souhaite dé/chiffrer sur plusieurs lignes et sans espace
- ```WITH_SPACE```: Lorsque l'on souhaite dé/chiffrer sur une seule ligne mais avec des espaces
- ```WITH_LINE_BREAK_AND_SPACE```: Lorsque l'on souhaite dé/chiffrer sur plusieurs lignes et avec des espaces
> Attention: Ce système Base64 n'est pas compatibles avec les systèmes existants sur le marché. Autrement dit, vous ne pouvez pas chiffrer avec la classe ```java.util.Base64``` et déchiffrer avec la classe ```com.jasonpercus.encryption.base64.Base64``` et inversement.

## 3. RSA

Cette classe sert pour chiffrer du texte ou tableau de bytes en tableau chiffré de bytes et inversement déchiffrer un tableau de bytes en texte. Elle s'appuie sur l'algorithme existant RSA. Voici un exemple de son utilisation:
```java
//Création d'un objet RSA
Cipher rsa = new RSA();

//Création d'une clée publique et une clée privée
Key publicKey  = rsa.generatePublicKey();
Key privateKey = rsa.generatePrivateKey();

//Il s'agit de mon texte à chiffrer avec RSA
byte[] toEncrypt =  "Mon texte converti en bytes".getBytes();

//Chiffrement & déchiffrement
byte[] encrypted = rsa.encrypt(publicKey, toEncrypt);
byte[] decrypted = rsa.decrypt(privateKey, encrypted);

//Affichages des résultats
System.out.println("Encrypted: " + new String(encrypted));
System.out.println("Decrypted: " + new String(decrypted));
```
Nous obtenons ce résultat
```
Encrypted: �3�d��t0��%�V�춠�:G�D#��Q�m�����o��b��QEZ37U q�ݨ3
Decrypted: Mon texte converti en bytes
```

> Attention: Ce système RSA n'est pas compatibles avec les systèmes existants sur le marché. Autrement dit, vous ne pouvez pas chiffrer avec la classe ```java.util.RSA``` et déchiffrer avec la classe ```com.jasonpercus.encryption.rsa.RSA``` et inversement.

## 4. AES

Cette classe sert pour chiffrer du texte ou tableau de bytes en tableau chiffré de bytes et inversement déchiffrer un tableau de bytes en texte. Elle s'appuie sur l'algorithme existant AES. Voici un exemple de son utilisation:
```java
//Création d'un objet AES
Cipher aes = new AES();

//Création d'une clée
Key key = aes.generateKey();

//Il s'agit de mon texte à chiffrer avec AES
byte[] toEncrypt =  "Mon texte converti en bytes".getBytes();

//Chiffrement & déchiffrement
byte[] encrypted = aes.encrypt(key, toEncrypt);
byte[] decrypted = aes.decrypt(key, encrypted);

//Affichages des résultats
System.out.println("Encrypted: " + new String(encrypted));
System.out.println("Decrypted: " + new String(decrypted));
```
Nous obtenons ce résultat
```
Encrypted: ��d�8X-��]���e������daR
Decrypted: Mon texte converti en bytes
```

> Attention: Ce système AES n'est pas compatibles avec les systèmes existants sur le marché. Autrement dit, vous ne pouvez pas chiffrer avec la classe ```java.util.AES``` et déchiffrer avec la classe ```com.jasonpercus.encryption.aes.AES``` et inversement.

## 5. JPS (Jason Percus Security)

Cette classe sert pour chiffrer du texte ou tableau de bytes en tableau chiffré de bytes et inversement déchiffrer un tableau de bytes en texte. Elle s'appuie sur un nouvel algorithme JPS. Voici un exemple de son utilisation:
```java
//Création d'un objet JPS
Cipher jps = new JPS();

//Création d'une clée
Key key = jps.generateKey();

//Il s'agit de mon texte à chiffrer avec JPS
byte[] toEncrypt =  "Mon texte converti en bytes".getBytes();

//Chiffrement & déchiffrement
byte[] encrypted = jps.encrypt(key, toEncrypt);
byte[] decrypted = jps.decrypt(key, encrypted);

//Affichages des résultats
System.out.println("Encrypted: " + new String(encrypted));
System.out.println("Decrypted: " + new String(decrypted));
```
Nous obtenons ce résultat
```
Encrypted:  ��w�
��]�M��#���P�_�����,3�	�:�eή$
Decrypted: Mon texte converti en bytes
```

# **Licence**
Le projet est sous licence "GNU General Public License v3.0"

## Accès au projet GitHub => [ici](https://github.com/josephbriguet01/Encryption "Accès au projet Git Encryption")