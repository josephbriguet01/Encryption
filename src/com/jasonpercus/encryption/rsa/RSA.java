/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.rsa;



import com.jasonpercus.encryption.Cipher;
import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.Type;
import com.jasonpercus.encryption.base64.Base64;
import com.jasonpercus.encryption.exception.KeySizeTooLongException;
import com.jasonpercus.encryption.exception.KeySizeTooSmallException;
import com.jasonpercus.encryption.exception.KeyTypeException;



/**
 * Cette classe permet de chiffrer et déchiffrer avec le chiffrage RSA
 * @author Briguet
 * @version 1.0
 */
public class RSA extends Cipher {

    
    
//ATTRIBUTS
    /**
     * Correpsond au nom de l'algorithme de chiffrement et de déchiffrement
     */
    public static final String ALGORITHM = "RSA";
    
    /**
     * Correspond à la taille minimale d'une clef RSA
     */
    public static final int KEY_SIZE_MIN = 4;
    
    /**
     * Correspond à la taille maximale d'une clef RSA
     */
    public static final int KEY_SIZE_MAX = 25;
    
    /**
     * Correspond à la chaine qui dit qu'il n'y a pas de texte à chiffrer
     */
    private static final byte[] EMPTY = {117, 78, 71, 88, 101, 90, 57, 49, 113, 65, 67, 101, 109, 51, 85, 107, 104, 116, 118, 106, 51, 78, 106, 98, 57, 85, 105, 49, 79, 116, 84, 111, 81, 101, 83, 112, 56, 79, 55, 97, 57, 49, 86, 78, 106, 109, 116, 115, 65, 112, 49, 51, 117, 119, 72, 54, 53, 52, 75, 119, 83, 85, 118, 119, 69, 107, 103, 97, 110, 85, 113, 114, 114, 87, 84, 76, 83, 56, 97, 54, 114, 74, 122, 77, 51, 70, 56, 89, 48, 89, 120, 90, 99, 49, 109, 118, 114, 66, 80, 73};

    /**
     * Correspond à la clée publique de ce moteur de (dé)chiffrage RSA
     */
    private KeyRSA keyPublic;
    
    /**
     * Correspond à la clée privée de ce moteur de (dé)chiffrage RSA
     */
    private KeyRSA keyPrivate;
    
    
    
//CONSTRUCTOR
    /**
     * Crée une instance d'un moteur de (dé)chiffrage RSA
     */
    public RSA() {
    }
    
    
    
//METHODES PUBLICS
    /**
     * Renvoie le type {@link Type#ASYMMETRIC}
     * @return Retourne le type {@link Type#ASYMMETRIC}
     */
    @Override
    public Type getType() {
        return Type.ASYMMETRIC;
    }
    
    /**
     * Génère une clef
     * @see #generatePublicKey() 
     * @see #generatePrivateKey() 
     * @return Retourne une clef générée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte car RSA utilise 2 clées. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public Key generateKey() {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Génère une clef de longueur size
     * @see #generatePublicKey(int) 
     * @see #generatePrivateKey(int) 
     * @param size Correspond à la longueur de la clef
     * @return Retourne une clef générée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte car RSA utilise 2 clées. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public Key generateKey(int size) {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Génère une clef de chiffrement RSA (dite publique)
     * @return Retourne une clef publique RSA
     */
    @Override
    public Key generatePublicKey() {
        return generatePublicKey(KEY_SIZE_MIN);
    }

    /**
     * Génère une clef de chiffrement RSA (dite publique) de longueur size
     * @param size Correspond à la longueur de la clef RSA
     * @return Retourne une clef publique RSA
     */
    @Override
    public Key generatePublicKey(int size) {
        generateKeys(size);
        return new KeyPublicRSA((this.keyPublic.e + "," + this.keyPublic.n).getBytes());
    }

    /**
     * Génère une clef de déchiffrement RSA (dite privée)
     * @return Retourne une clef privée RSA
     */
    @Override
    public Key generatePrivateKey() {
        return generatePrivateKey(KEY_SIZE_MIN);
    }

    /**
     * Génère une clef de déchiffrement RSA (dite privée) de longueur size
     * @param size Correspond à la longueur de la clef RSA
     * @return Retourne une clef privée RSA
     */
    @Override
    public Key generatePrivateKey(int size) {
        generateKeys(size);
        return new KeyPrivateRSA((this.keyPrivate.e + "," + this.keyPrivate.n).getBytes());
    }
    
    /**
     * Chiffre les données
     * @param key Correspond à la clef de chiffrement publique RSA
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées en RSA
     */
    @Override
    public byte[] encrypt(Key key, byte[] datas) {
        if(key == null) throw new java.lang.NullPointerException("key is null.");
        if(datas == null) throw new java.lang.NullPointerException("datas is null.");
        if(datas.length <= 0) datas = EMPTY;
        
        if(key instanceof KeyPublicRSA){
            String[] split = new String(key.getKey()).split(",");
            KeyRSA kp = new KeyRSA(new java.math.BigInteger(split[0]), new java.math.BigInteger(split[1]));
            try {
                
                java.math.BigInteger message = RSAUtil.bytesToNumber(new Base64().encrypt(datas));
                
                java.math.BigInteger encrypted;
                if (message.compareTo(java.math.BigInteger.ZERO) < 0) {
                    throw new Exception("Le message ne peut etre chiffre, car il est negatif ");
                }
                if (message.compareTo(kp.getModulo()) < 0) {
                    encrypted = RSAUtil.modularPower(message, kp.getExponent(), kp.getModulo());
                } else {
                    int incr = kp.getModulo().toString().length() - 1;
                    if (incr <= 0) {
                        throw new Exception("Le message ne peut etre decoupe de telle sorte qu'il soit dans [0," + kp.getModulo().subtract(java.math.BigInteger.ONE) + "]");
                    }
                    String param = message.toString();
                    if ((param.length() % incr) != 0) {
                        int count = incr - (param.length() % incr);
                        for (int i = 1; i <= count; i++) {
                            param = "0" + param;
                        }
                    }
                    int begin = 0;
                    String result = "";
                    while (begin < param.length()) {
                        int end = ((begin + incr) < param.length()) ? (begin + incr) : param.length();
                        java.math.BigInteger aux = new java.math.BigInteger(param.substring(begin, end));
                        String value = (RSAUtil.modularPower(aux, kp.getExponent(), kp.getModulo())).toString();
                        if (value.length() > (incr + 1)) {
                            throw new Exception("Erreur Conception Interne");
                        }
                        int size = (incr + 1) - value.length();
                        for (int i = 1; i <= size; i++) {
                            value = "0" + value;
                        }
                        result += value;
                        begin += incr;
                    }
                    encrypted = new java.math.BigInteger(result);
                }
                return RSAUtil.numberToBytes(encrypted);
            } catch (Exception ex) {
                java.util.logging.Logger.getLogger(RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            }
        }else{
            throw new KeyTypeException("key must be a "+KeyPublicRSA.class.getCanonicalName()+". However you have put a "+key.getClass().getCanonicalName());
        }
        return null;
    }

    /**
     * Déchiffre les données RSA
     * @param key Correpsond à la clef de déchiffrement privée RSA
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     */
    @Override
    public byte[] decrypt(Key key, byte[] datas) {
        if(key == null) throw new java.lang.NullPointerException("key is null.");
        if(datas == null) throw new java.lang.NullPointerException("datas is null.");
        
        if(key instanceof KeyPrivateRSA){
            String[] split = new String(key.getKey()).split(",");
            KeyRSA kr = new KeyRSA(new java.math.BigInteger(split[0]), new java.math.BigInteger(split[1]));
            try {
                java.math.BigInteger message = RSAUtil.bytesToNumber(datas);
                java.math.BigInteger decrypted;
                
                if (message.compareTo(java.math.BigInteger.ZERO) < 0) {
                    throw new Exception("Le message ne peut etre chiffre, car il est negatif ");
                }
                if (message.compareTo(kr.getModulo()) < 0) {
                    decrypted = RSAUtil.modularPower(message, kr.getExponent(), kr.getModulo());
                } else {
                    int incr = kr.getModulo().toString().length();
                    if (incr <= 0) {
                        throw new Exception("Le message ne peut etre decoupe de telle sorte qu'il soit dans [0," + kr.getModulo().subtract(java.math.BigInteger.ONE) + "]");
                    }
                    String param = message.toString();
                    if ((param.length() % incr) != 0) {
                        int count = incr - (param.length() % incr);
                        for (int i = 1; i <= count; i++) {
                            param = "0" + param;
                        }
                    }
                    int begin = 0;
                    String result = "";
                    while (begin < param.length()) {
                        java.math.BigInteger aux = new java.math.BigInteger(param.substring(begin, begin + incr));
                        String value = (RSAUtil.modularPower(aux, kr.getExponent(), kr.getModulo())).toString();
                        if (value.length() < (incr - 1)) {
                            int count = incr - 1 - value.length();
                            for (int i = 1; i <= count; i++) {
                                value = "0" + value;
                            }
                        }
                        result += value;
                        begin += incr;
                    }			
                    decrypted = new java.math.BigInteger(result);
                }
                
                byte[] res = new Base64().decrypt(RSAUtil.numberToBytes(decrypted));
                if(res.length == EMPTY.length){
                    boolean eq = true;
                    for(int i=0;i<res.length;i++){
                        if(res[i] != EMPTY[i]){
                            eq = false;
                            break;
                        }
                    }
                    if(eq) return new byte[0];
                }
                return res;
            } catch (Exception ex) {
                java.util.logging.Logger.getLogger(RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            }
        }else{
            throw new KeyTypeException("key must be a "+KeyPrivateRSA.class.getCanonicalName()+". However you have put a "+key.getClass().getCanonicalName());
        }
        return null;
    }

    /**
     * Chiffre les données
     * @see #encrypt(com.jasonpercus.encryption.Key, byte[])
     * @see #encrypt(com.jasonpercus.encryption.Key, java.lang.String) 
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte car RSA a besoin d'une clef pour chiffrer. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public byte[] encrypt(byte[] datas) {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Déchiffre les données
     * @see #decrypt(com.jasonpercus.encryption.Key, byte[]) 
     * @see #decrypt(com.jasonpercus.encryption.Key, java.lang.String) 
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte car RSA a besoin d'une clef pour déchiffrer. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public byte[] decrypt(byte[] datas) {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    
//METHODE PRIVATE
    /**
     * Génère les deux clefs publique et privée. Comme elle sont liées. Dès que l'une est créé on bloque l'écrasement éventuelle d'un nouvel appel de cette méthode. Ainsi, on garde les deux clefs en mémoire dans l'objet
     * @param size Correspond à la taille des clefs à générer
     */
    private void generateKeys(int size){
        if(this.keyPublic == null && this.keyPrivate == null){
            if(size < KEY_SIZE_MIN) throw new KeySizeTooSmallException("The size of the key is less than "+KEY_SIZE_MIN+".");
            else if(size > KEY_SIZE_MAX) throw new KeySizeTooLongException("The size of the key is greater than "+KEY_SIZE_MAX+".");
            else{
                try {
                    java.math.BigInteger[] primes = RSAUtil.generateTwoPrimes(size);
                    KeyRSA[] keys = RSAUtil.buildKeysOf(primes[0], primes[1]);
                    if (keys[0] == null || keys[1] == null) {
                        throw new Exception("L'une ou l'autre des deux cles est/sont incorrecte(s)");
                    }
                    if (keys[0].getModulo() != keys[1].getModulo()) {
                        throw new Exception("Les deux cles n'ont pas le meme modulo");
                    }
                    java.math.BigInteger phi = RSAUtil.phi(keys[0].getModulo());
                    if (keys[0].getExponent().compareTo(java.math.BigInteger.ONE) <= 0 || keys[0].getExponent().compareTo(phi) >= 0) {
                        throw new Exception("L'exposant de la cle publique est incorrect");
                    }
                    if (keys[1].getExponent().compareTo(java.math.BigInteger.ONE) <= 0 || keys[1].getExponent().compareTo(phi) >= 0) {
                        throw new Exception("L'exposant de la cle privee est incorrect");
                    }
                    this.keyPublic  = keys[0];
                    this.keyPrivate = keys[1];
                } catch (Exception ex) {
                    java.util.logging.Logger.getLogger(RSA.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
                }
            }
        }
    }
    
    
    
//CLASS
    /**
     * @author Charles Mouté
     * <p>
     * Cette classe represente une cle en terme de paires (e,n) ou e peut etre
     * l'exposant de chiffrement ou de dechiffrement et n est le modulo. Elle est
     * utilisee particulierement dans RSA.
     * </p>
     */
    private static class KeyRSA {

        /**
         * Exposant de chiffrement ou de dechiffrement.
         */
        private java.math.BigInteger e;

        /**
         * Modulo
         */
        private java.math.BigInteger n;

        public KeyRSA(java.math.BigInteger e, java.math.BigInteger n) {
            this.e = e;
            this.n = n;
        }

        /**
         * Affecte un nouvel exposant a la cle.
         *
         * @param e Nouvel exposant
         */
        public void setExponent(java.math.BigInteger e) {
            this.e = e;
        }

        /**
         * @return L'exposant associe a la cle.
         */
        public java.math.BigInteger getExponent() {
            return this.e;
        }

        /**
         * Affecte un nouveau modulo a la cle.
         *
         * @param n Nouveau modulo.
         */
        public void setModulo(java.math.BigInteger n) {
            this.n = n;
        }

        /**
         * @return Le modulo associe a la cle.
         */
        public java.math.BigInteger getModulo() {
            return this.n;
        }

        @Override
        public String toString() {
            return "(" + e + "," + n + ")";
        }
    }
    
    /**
     * @author Charles Mouté
     * <p>
     * Cette classe contient la plupart des fonctions utilisees dans RSA de Rivest
     * Shamir Adleman.
     * </p>
     */
    private static class RSAUtil {

        /**
         * <p>
         * Calcule la puissance modulaire de a^e mod n</p>
         *
         * @param a Parametre 1
         * @param e parametre 2
         * @param n parametre 3
         * @return (a puissance e) modulo n
         */
        public static final java.math.BigInteger modularPower(java.math.BigInteger a, java.math.BigInteger e, java.math.BigInteger n) throws Exception {
            if (a == null || e == null || n == null) {
                throw new Exception("Un des parametres n'a pas ete initialise");
            }
            return a.modPow(e, n);
        }

        /**
         * Calcule a puissance b
         *
         * @param a Nombre a elever a la puissance
         * @param b Exposant de la puissance
         * @return a puissance b
         * @throws Exception Erreur generee lorsque le code ne s'est pas deroule
         * correctement.
         */
        public static final java.math.BigInteger pow(java.math.BigInteger a, int b) throws Exception {
            if (a == null) {
                throw new Exception("Le parametre a eleve a la puissance n'a pas ete initialise");
            }
            return (a.pow(b));
        }

        /**
         * <p>
         * Dit si le parametre est un nombre premier ou pas</p>
         *
         * @param p Nombre a tester la primalite.
         * @return True si le parametre est premier, false dans le cas contraire.
         */
        public static final boolean isPrime(java.math.BigInteger p) {
            if (p == null) {
                return false;
            }
            return p.isProbablePrime(5);
        }
        
        /**
         * Calcule le nombre de bits qui constitue le parametre
         *
         * @param param Parametre dont le nombre de bits doit etre retourne
         * @return -1 si le parametre est incorrecte sinon le nombre de bits
         * constituant le parametre.
         */
        public static final int getSizeOf(java.math.BigInteger param) {
            if (param == null) {
                return -1;
            }
            return param.bitLength();
        }

        /**
         * Renvoie un nombre aleatoire dans [2^size, (2^(size+1)-1)]
         *
         * @param size Nombre de bit du nombre a generer
         * @return Un nombre de size bits.
         */
        public static final java.math.BigInteger random(int size) {
            java.math.BigInteger output = java.math.BigInteger.ONE;
            for (--size; size > 0; --size) {
                output = (output.multiply(java.math.BigInteger.valueOf(2))).add((java.math.BigInteger.valueOf((long) (Math.round(Math.random())))));
            }
            return output;
        }

        /**
         * Genere un nombre aleatoire compris dans l'intervalle fermee [min,max]
         *
         * @param min Minimum de l'intervalle
         * @param max Maximum de l'intervalle
         * @return Un nombre compris entre min et max
         * @throws Exception Erreur generee lorsque le code ne s'est pas deroule
         * correctement.
         */
        public static final java.math.BigInteger random(java.math.BigInteger min, java.math.BigInteger max) throws Exception {
            if (min == null || max == null) {
                throw new Exception("L'une des valeurs, min ou max est incorrecte");
            }
            if (min.compareTo(max) >= 0) {
                throw new Exception("L'intervalle de generation est incorrect car le minimun = " + min + ">= maximun = " + max);
            }
            java.math.BigDecimal alea = new java.math.BigDecimal(Math.random());
            java.math.BigDecimal _max = new java.math.BigDecimal(max), _min = new java.math.BigDecimal(min);
            return ((alea.multiply(_max)).add(_min)).toBigInteger();
        }

        /**
         * Dit si le parametre est impair ou pas.
         *
         * @param p Parametre dont la parite sera testee.
         * @return true si le parametre est de parite impaire, false dans le cas
         * contraire.
         */
        public static final boolean isOdd(java.math.BigInteger p) {
            if (p == null) {
                return false;
            }
            return (p.and(java.math.BigInteger.ONE).compareTo(java.math.BigInteger.ONE) == 0);
        }

        /**
         * Genere un nombre premier de size bits.
         *
         * @param size Taille du nombre premiers a generer.
         * @return un nombre premier dans [2^size, (2^(size+1)-1)] , si size >=0
         * bits
         * @throws Exception Erreur due a un mauvaise execution du code.
         */
        public static final java.math.BigInteger findPrime(int size) throws Exception {
            java.math.BigInteger count = (size <= 0) ? java.math.BigInteger.ONE : java.math.BigInteger.valueOf(2).pow(size);
            java.math.BigInteger value = RSAUtil.random(size);

            if (!RSAUtil.isOdd(value)) {
                value = value.add(java.math.BigInteger.ONE);
            }
            while (!RSAUtil.isPrime(value) && (count.compareTo(java.math.BigInteger.ZERO) > 0)) {
                value = value.add(java.math.BigInteger.valueOf(2));
                count = count.subtract(java.math.BigInteger.ONE);
            }
//            String info = "[" + (java.math.BigInteger.valueOf(2).pow(size)) + ", " + (java.math.BigInteger.valueOf(2).pow(size + 1).subtract(java.math.BigInteger.ONE)) + "]";
            if (!RSAUtil.isPrime(value)) {
                return findPrime(size);
//                throw new Exception("Il n'existe aucun nombres premiers dans " + info);
            }
            return value;
        }

        /**
         * Genere deux nombres premiers de size bits.
         *
         * @param size Nombre de bits des nombres a generer.
         * @return Une paire de deux nombres premiers distincts
         * @throws Exception Erreur due a un mauvaise execution du code.
         */
        public static final java.math.BigInteger[] generateTwoPrimes(int size) throws Exception {
            if (size < 3) {
                throw new Exception("Impossible de trouver deux nombres premiers de taille " + size);
            }
            java.math.BigInteger p = RSAUtil.findPrime(size);
            java.math.BigInteger q;
            do {
                q = RSAUtil.findPrime(size);
            } while (p.equals(q));
            java.math.BigInteger[] result = new java.math.BigInteger[2];
            result[0] = p;
            result[1] = q;
            return result;
        }

        /**
         * Generer une cle publique et une cle privee a partir des deux nombres
         * premiers en parametre.
         *
         * @param p Premier nombre premier
         * @param q Deuxieme nombre premier
         * @return Un couple cle publique et cle privee.
         * @throws Exception Erreur due a un mauvaise execution du code.
         */
        public static final KeyRSA[] buildKeysOf(java.math.BigInteger p, java.math.BigInteger q) throws Exception {
            if (!RSAUtil.isPrime(p)) {
                throw new Exception("Le premier parametre n'est pas un nombre premier");
            }
            if (!RSAUtil.isPrime(q)) {
                throw new Exception("Le deuxieme parametre n'est pas un nombre premier");
            }
            KeyRSA[] keys = new KeyRSA[2];
            java.math.BigInteger n = p.multiply(q);
            java.math.BigInteger phi = (p.subtract(java.math.BigInteger.ONE)).multiply(q.subtract(java.math.BigInteger.ONE));
            java.math.BigInteger e = RSAUtil.random(java.math.BigInteger.ONE, phi.subtract(java.math.BigInteger.ONE));
            java.math.BigInteger[] r = RSAUtil.extendedEuclide(e, phi);
            while (r[0].compareTo(java.math.BigInteger.ONE) != 0 || (r[1].compareTo(java.math.BigInteger.ONE) <= 0 || r[1].compareTo(phi) >= 0) || e.equals(r[1])) {
                e = RSAUtil.random(java.math.BigInteger.ONE, phi.subtract(java.math.BigInteger.ONE));
                r = RSAUtil.extendedEuclide(e, phi);
            }
            java.math.BigInteger d = r[1];
            keys[0] = new KeyRSA(e, n);
            keys[1] = new KeyRSA(d, n);
            return keys;
        }

        /**
         * <p>
         * Retourne un triplet (d,x,y) tel que ax+by = d, ou d est le pgcd de a et b
         * et x et y sont les nombres de Bezout.
         * </p>
         *
         * @param a Premier parametre
         * @param b Deuxieme parametre
         * @return un triplet (d,x,y)
         */
        public static final java.math.BigInteger[] extendedEuclide(java.math.BigInteger a, java.math.BigInteger b) {

            java.math.BigInteger[] result = null;

            if (a != null && b != null) {
                java.math.BigInteger u0 = java.math.BigInteger.ONE, v0 = java.math.BigInteger.ZERO;
                java.math.BigInteger u = java.math.BigInteger.ZERO, v = java.math.BigInteger.ONE;
                java.math.BigInteger e0 = a, pgcd = b;
                java.math.BigInteger q, r, aux;

                q = e0.divide(pgcd);
                r = e0.remainder(pgcd);

                while (r.compareTo(java.math.BigInteger.ZERO) > 0) {
                    aux = pgcd;
                    pgcd = e0.subtract(q.multiply(pgcd));
                    e0 = aux;

                    aux = u;
                    u = u0.subtract(q.multiply(u));
                    u0 = aux;

                    aux = v;
                    v = v0.subtract(q.multiply(v));
                    v0 = aux;

                    q = e0.divide(pgcd);
                    r = e0.remainder(pgcd);
                }

                result = new java.math.BigInteger[3];
                result[0] = pgcd;
                result[1] = u;
                result[2] = v;
            }
            return result;
        }

        /**
         * <p>
         * Calcule l'inverse de a modulo b. En realite la valeur retourne correspond
         * a la valeur absolue de l'element se trouvant a la position 1 du resultat
         * de extendedEuclide(a,b)
         * </p>
         *
         * @param a Premier parametre
         * @param b Deuxieme parametre
         * @return L'inverse de a modulo b
         * @see #extendedEuclide(long, long)
         */
        public static final java.math.BigInteger inverse(java.math.BigInteger a, java.math.BigInteger b) {
            java.math.BigInteger val = null;
            if (a != null && b != null) {
                val = a.modInverse(b);
            }
            return val;
        }

        /**
         * Decompose un nombre strictement positif en produit de facteurs premiers.
         *
         * @param n Nombre a decomposer
         * @return La decomposition sous forme de liste de Nombre de la forme
         * (nombre premier,exposant) Ex: (2,4) = 2^4 est la decomposition de 16
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static final java.util.ArrayList<Number> decompose(java.math.BigInteger n) throws Exception {

            if (n == null || n.compareTo(java.math.BigInteger.ZERO) <= 0) {
                throw new Exception("La decomposition de nombre <=0 n'est pas possible");
            }
            java.util.ArrayList<Number> res = new java.util.ArrayList<>();
            if (n.compareTo(java.math.BigInteger.ONE) == 0) {
                Number number = new Number(java.math.BigInteger.valueOf(2), 0);
                res.add(number);
                return res;
            }
            java.math.BigInteger param = n, prime = java.math.BigInteger.ONE;
            int e = 0;
            while (true) {

                while (!RSAUtil.isPrime(prime)) {
                    prime = prime.add(java.math.BigInteger.ONE);
                }
                e = 0;
                if (param.compareTo(java.math.BigInteger.ONE) == 0) {
                    break;
                }
                java.math.BigInteger q = param.divide(prime);
                java.math.BigInteger r = param.remainder(prime);
                while (r.compareTo(java.math.BigInteger.ZERO) == 0) {
                    e++;
                    param = q;
                    q = param.divide(prime);
                    r = param.remainder(prime);
                }
                if (e > 0) {
                    Number number = new Number(prime, e);
                    res.add(number);
                }
                prime = prime.add(java.math.BigInteger.ONE);
            }
            return res;
        }

        /**
         * <p>
         * Calcule l'indicatrice d'Euler</p>
         *
         * @param n Modulo
         * @return L'indicatrice du parametre
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static final java.math.BigInteger phi(java.math.BigInteger n) throws Exception {
            java.util.ArrayList<Number> factors = RSAUtil.decompose(n);
            java.math.BigInteger phi = java.math.BigInteger.ONE;
            for (int i = 0; i < factors.size(); i++) {
                Number number = factors.get(i);
                phi = phi.multiply((number.getPrime().subtract(java.math.BigInteger.ONE)).multiply(RSAUtil.pow(number.getPrime(), number.getExponent() - 1)));
            }
            return phi;
        }

        /**
         * Trouve l'autre cle a partir de la cle, generalement cle publique, passe
         * en parametre
         *
         * @param key Cle publique
         * @return Cle secrete
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static final KeyRSA findOtherKey(KeyRSA key) throws Exception {
            if (key == null) {
                throw new Exception("La cle est incorrecte");
            }
            java.math.BigInteger phi = RSAUtil.phi(key.getModulo());
            if (key.getExponent().compareTo(java.math.BigInteger.ONE) <= 0 || key.getExponent().compareTo(phi) >= 0) {
                throw new Exception("L'exposant n'est pas dans l'intervalle ]1,phi(" + key.getModulo() + ")[");
            }
            return (new KeyRSA(RSAUtil.inverse(key.getExponent(), phi), key.getModulo()));
        }

        /**
         * Converti le parametre en chaine de caractere binaire
         *
         * @param number Nombre a convertir.
         * @return Chaine de caractere representant la conversion en nombre binaire
         * du parametre
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static String bigIntegerToBinaryString(java.math.BigInteger number) throws Exception {
            if (number == null || number.compareTo(java.math.BigInteger.ZERO) < 0) {
                throw new Exception("Le nombre ne peut etre converti en binaire");
            }
            String result = null;
            if (number.compareTo(java.math.BigInteger.ZERO) >= 0) {
                result = "";
                java.math.BigInteger val = number;
                while (val.compareTo(java.math.BigInteger.ONE) > 0) {
                    result = val.mod(java.math.BigInteger.valueOf(2)) + result;
                    val = val.divide(java.math.BigInteger.valueOf(2));
                }
                result = val + result;
                if ((result.length() % 8) != 0) {
                    int size = 8 - (result.length() % 8);
                    for (int i = 1; i <= size; i++) {
                        result = "0" + result;
                    }
                }
            }
            return result;
        }

        /**
         * Converti une chaine binaire en un nombre
         *
         * @param param Chaine binaire
         * @return La conversion en decimal du parametre
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static java.math.BigInteger binaryStringToBigInteger(String param) throws Exception {
            if (!Binary.isBinaryRepresentation(param)) {
                throw new Exception("Le parametre n'est pas une chaine binaire");
            }
            int pow = 0;
            java.math.BigInteger result = java.math.BigInteger.ZERO;
            for (int i = param.length() - 1; i >= 0; i--) {
                java.math.BigInteger aux = (param.charAt(i) == '1' ? java.math.BigInteger.ONE : java.math.BigInteger.ZERO);
                java.math.BigInteger value = java.math.BigInteger.valueOf(2).pow(pow);
                result = result.add(aux.multiply(value));
                pow++;
            }
            return result;
        }

        /**
         * Converti la chaine de caractere en un nombre
         *
         * @param message Chaine de caractere a convertir
         * @return Un nombre identifiant la chaine de caractere
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static java.math.BigInteger stringToNumber(String message) throws Exception {
            if (message == null || message.length() == 0) {
                throw new Exception("Le message ne peut etre transforme en un nombre unique");
            }
            String binary = "";
            for (int i = 0; i < message.length(); i++) {
                int aux = message.charAt(i);
                binary += Binary.intToBinaryString(aux);
            }
            return RSAUtil.binaryStringToBigInteger(binary);
        }

        public static java.math.BigInteger bytesToNumber(byte[] message) throws Exception {
            if (message == null || message.length == 0) {
                throw new Exception("byte array to encrypt is null !");
            }
            String binary = "";
            for (int i = 0; i < message.length; i++) {
                int aux = message[i] + 128;
                binary += Binary.intToBinaryString(aux);
            }
            return RSAUtil.binaryStringToBigInteger(binary);
        }

        /**
         * Si possible converti un nombre en une chaine de caractere Ascii.
         *
         * @param number Nombre a transformer
         * @return Une chaine de caractere Ascii
         * @throws Exception Erreur generer lorsque le code ne se deroule pas
         * correctement.
         */
        public static String numberToString(java.math.BigInteger number) throws Exception {
            String binary = RSAUtil.bigIntegerToBinaryString(number);
            if (!Binary.isBinaryRepresentation(binary)) {
                throw new Exception("L'entier ne peut etre converti en chaine de caractere");
            }
            String param = binary;
            if ((param.length() % 8) != 0) {
                int count = 8 - (param.length() % 8);
                for (int i = 1; i <= count; i++) {
                    param = "0" + param;
                }
            }

            int begin = 0, incr = 8;
            String result = "";
            while (begin < param.length()) {
                String aux = param.substring(begin, begin + incr);
                int value = Binary.binaryStringToInt(aux);
                if (value < 0 || value > 255) {
                    throw new Exception("L'entier ne peut etre converti en chaine de caractere ASCii");
                }
                result += ((char) value);
                begin += incr;
            }
            return result;
        }

        public static byte[] numberToBytes(java.math.BigInteger number) throws Exception {
            String binary = RSAUtil.bigIntegerToBinaryString(number);
            if (!Binary.isBinaryRepresentation(binary)) {
                throw new Exception("L'entier ne peut etre converti en chaine de caractere");
            }
            String param = binary;
            if ((param.length() % 8) != 0) {
                int count = 8 - (param.length() % 8);
                for (int i = 1; i <= count; i++) {
                    param = "0" + param;
                }
            }

            int begin = 0, incr = 8;
            java.util.List<Integer> list = new java.util.ArrayList<>();
            while (begin < param.length()) {
                String aux = param.substring(begin, begin + incr);
                int value = Binary.binaryStringToInt(aux);
                if (value < 0 || value > 255) {
                    throw new Exception("L'entier ne peut etre converti en chaine de caractere ASCii");
                }
                list.add(value);
                begin += incr;
            }
            byte[] array = new byte[list.size()];
            for(int i=0;i<list.size();i++){
                array[i] = (byte)(list.get(i)-128);
            }
            return array;
        }

    }
    
    /**
     * @author Charles Mouté
     * <p>
     * Cette classe represente un nombre sous la forme d'un nombre premier puissance
     * un valeur. Elle sera utilise pour la factorisation d'un nombre en nombre
     * premiers. Ainsi par exemple 16 sera 2^4, ou 2 est le facteur premier, ^
     * l'elevation a la puissance et 4 l'exposant de la puissance.
     * </p>
     */
    private static class Number {

        /**
         * Le nombre premier
             *
         */
        private java.math.BigInteger prime;

        /**
         * L'exposant de la puissance
             *
         */
        private int e;

        /**
         * Cree une instance de Nombre avec un unique facteur premier
         *
         * @param prime Facteur premier
         * @param e Exposant de la puissance
         * @throws Exception Erreur generee lorsque prime n'est pas un nombre
         * premier.
         */
        public Number(java.math.BigInteger prime, int e) throws Exception {
            this.setPrime(prime);
            this.setExponent(e);
        }

        /**
         * Affecte le parametre comme le nouveau facteur
         *
         * @param p Nouveau facteur
         * @throws Exception Erreur generee lorsque le parametre n'est pas un nombre
         * premier.
         */
        public void setPrime(java.math.BigInteger p) throws Exception {
            if (!RSAUtil.isPrime(p)) {
                throw new Exception("Le facteur n'est pas un nombre premier");
            }
            this.prime = p;
        }

        /**
         * @return Le facteur du nombre
         */
        public java.math.BigInteger getPrime() {
            return this.prime;
        }

        /**
         * Affecte le parametre comme le nouvel exposant de la puissance
         *
         * @param e Nouvel exposant de la puissance
         */
        public void setExponent(int e) {
            this.e = e;
        }

        /**
         * @return L'exposant de la puissance.
         */
        public int getExponent() {
            return this.e;
        }

        @Override
        public String toString() {
            return prime + "^" + e;
        }
    }
    
    /**
     * @author Charles Mouté
     * <p>
     * Binary est une classe gerant les transformations entiers-binaire et
     * binaire-entiers</p>
     */
    private static class Binary {



        /**
         * <p>
         * Si le parametre est une representation d'un nombre binaire, elle retourne
         * un buffer de byte. Selon le principe que un caractere est code sur 8
         * bits.
         * </p>
         *
         * @param param Representation binaire a convertir en byte
         * @return Valeur decimal du parametre
         * @throws Exception Erreur lancee lorsque le code ne peut s'executer
         * correctement.
         */
        public static final java.util.ArrayList<Integer> binaryStringToIntTable(String param) throws Exception {
            if (!Binary.isBinaryRepresentation(param)) {
                throw new Exception("Erreur Lors de la conversion binaire-entier");
            }

            if ((param.length() % 8) != 0) {
                throw new Exception("La chaine binaire ne peut etre converti en suite d'entiers");
            }

            int i = 0, incr = 8;
            java.util.ArrayList<Integer> buffer = new java.util.ArrayList<>();
            while (i < param.length()) {
                int end = ((i + incr) < param.length()) ? (i + incr) : param.length();
                String substr = param.substring(i, end);
                int val = binaryStringToInt(substr);
                if (val < 0 || val > 255) {
                    throw new Exception("Erreur La chaine binaire ne peut etre converti en Suite d'entiers");
                }
                buffer.add(val);
                i += incr;
            }
            return buffer;
        }

        /**
         * <p>
         * Retourne la conversion en decimal du parametre si il existe, sinon -1</p>
         *
         * @param param Representation Binaire
         * @return La conversion en decimal du parametre.
         * @throws Exception Erreur lancee si la consversion n'a pu se faire
         */
        public static final int binaryStringToInt(String param) throws Exception {
            if (!Binary.isBinaryRepresentation(param)) {
                throw new Exception("Erreur Lors de la conversion binaire-entier");
            }
            int pow = 0;
            int result = 0;
            for (int i = param.length() - 1; i >= 0; i--) {
                result += (param.charAt(i) == '1' ? 1 : 0) * ((int) Math.pow(2, pow));
                pow++;
            }
            return result;
        }

        /**
         * <p>
         * Converti le parametre a une chaine binaire.</p>
         *
         * @param param Parametre dont on veut obtenir une representation binaire.
         * @return null si la conversion est impossible, sinon la representation
         * binaire du parametre.
         */
        public static final String intToBinaryString(java.util.ArrayList<Integer> param) {
            String result = null;
            if (param != null && param.size() > 0) {
                result = "";
                for (int i = 0; i < param.size(); i++) {
                    result += Binary.intToBinaryString(param.get(i));
                }
            }
            return result;
        }

        /**
         * <p>
         * Retourne une chaine representant la conversion binaire du parametre.</p>
         *
         * @param param Parametre a convertir.
         * @return La conversion binaire de param.
         */
        public static final String intToBinaryString(int param) {
            String result = null;
            if (param >= 0) {
                result = "";
                int val = param;
                /*while( val!=0){
                                    int bit =(val&0x1) ;				
                                    result = bit + result ;
                                    val = val >> 1;
                            }*/
                while (val > 1) {
                    result = ((int) (val % 2)) + result;
                    val /= 2;
                }
                result = val + result;
                if ((result.length() % 8) != 0) {
                    int size = 8 - (result.length() % 8);
                    for (int i = 1; i <= size; i++) {
                        result = "0" + result;
                    }
                }
            }
            return result;
        }

        /**
         * <p>
         * Dit si le prametre est la representation d'un nombre binaire.</p>
         *
         * @param param Chaine a verifier.
         * @return True si param est un nombre binaire et False dans le cas
         * contraire.
         */
        public static final boolean isBinaryRepresentation(String param) {
            if (param != null && param.length() > 0) {
                boolean result = true;
                for (int i = 0; i < param.length(); i++) {
                    if (param.charAt(i) != '0' && param.charAt(i) != '1') {
                        result = false;
                        break;
                    }
                }
                return result;

            } else {
                return false;
            }
        }

        /**
         * <p>
         * Calcule le XOR de a et b. A condition que a et b soit des representations
         * de nombres binaires.</p>
         *
         * @param a Operande 1
         * @param b Operande 2
         * @return Ou( et(a,non(b)), et(non(a),b)) si la taille de a est identique a
         * la taille de b et a et b sont different de null, sinon null.
         * @throws Exception Erreur lancee,entre autre, lorsque les parametres ne
         * sont pas des chaines Binaire.
         */
        public static final String xor(String a, String b) throws Exception {
            String result = null;
            if (!Binary.isBinaryRepresentation(a) || !Binary.isBinaryRepresentation(b)) {
                throw new Exception("Erreur lors de l'application de Xor. Un parametre n'est pas une chaine binaire");
            }

            result = "";
            String param1 = a;
            String param2 = b;

            if (param1.length() < param2.length()) {
                for (int i = 0; i < (param2.length() - param1.length()); i++) {
                    param1 = "0" + param1;
                }
            } else if (param2.length() < param1.length()) {
                for (int i = 0; i < (param1.length() - param2.length()); i++) {
                    param2 = "0" + param2;
                }
            }

            for (int i = 0; i < param1.length(); i++) {
                result += Integer.parseInt("" + param1.charAt(i)) ^ Integer.parseInt("" + param2.charAt(i));
            }

            return result;
        }



    }
    
    
    
}