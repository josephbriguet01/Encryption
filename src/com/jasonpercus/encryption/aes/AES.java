/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.aes;



import com.jasonpercus.encryption.Cipher;
import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.Type;
import com.jasonpercus.encryption.base64.Base64;
import com.jasonpercus.encryption.exception.KeySizeException;
import com.jasonpercus.encryption.exception.KeySizeTooLongException;
import com.jasonpercus.encryption.exception.KeySizeTooSmallException;



/**
 * Cette classe permet de chiffrer et déchiffrer avec le chiffrage AES
 * @author Briguet
 * @version 1.2
 */
public class AES extends Cipher {


    
//ATTRIBUTS
    /**
     * Correpsond au nom de l'algorithme de chiffrement et de déchiffrement
     */
    public static final String ALGORITHM = "AES";
    
    /**
     * Correspond à la longueur minimale de la clef AES
     */
    public static final int KEY_SIZE_MIN = 128;
    
    /**
     * Correspond à la longueur maximale de la clef AES (d'autres programmes java permettent de créer un clef de taille supérieure à 16)
     */
    public static final int KEY_SIZE_MAX = 256;

    
    
//CONSTRUCTOR
    /**
     * Crée une instance d'un moteur de (dé)chiffrage AES
     */
    public AES() {
    }
    
    
    
//METHODES PUBLICS
    /**
     * Renvoie le type {@link Type#SYMMETRIC}
     * @return Retourne le type {@link Type#SYMMETRIC}
     */
    @Override
    public Type getType() {
        return Type.SYMMETRIC;
    }
    
    /**
     * Génère une clef AES de longueur KEY_SIZE_MIN
     * @return Retourne une clef générée
     */
    @Override
    public KeyAES generateKey() throws KeySizeException {
        return generateKey(KEY_SIZE_MIN);
    }

    /**
     * Génère une clef AES de longueur size
     * @param size Correspond à la longueur de la clef AES
     * @return Retourne une clef AES générée
     */
    @Override
    public KeyAES generateKey(int size) throws KeySizeException {
        if(size < KEY_SIZE_MIN) throw new KeySizeTooSmallException("The size of the key is less than "+KEY_SIZE_MIN+".");
        else if(size > KEY_SIZE_MAX) throw new KeySizeTooLongException("The size of the key is greater than "+KEY_SIZE_MAX+".");
        else{
            try {
                
                
                /*String base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                String chain = "";
                for(int i=0;i<size;i++){
                    chain += base.charAt((int) (Math.random() * base.length()));
                }
                return new KeyAES(chain.getBytes());*/


                javax.crypto.KeyGenerator generator = javax.crypto.KeyGenerator.getInstance("AES");
                generator.init(128);

                javax.crypto.SecretKey key = generator.generateKey();
                return new KeyAES(new String(new Base64().encrypt(key.getEncoded())));
            } catch (java.security.NoSuchAlgorithmException ex) {
                java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
                return null;
            }
        }
    }

    /**
     * Génère une clef AES de longueur KEY_SIZE_MIN (AES est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey())
     * @return Retourne une clef générée
     */
    @Override
    public KeyAES generatePublicKey() {
        return generateKey();
    }

    /**
     * Génère une clef AES de longueur size (AES est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey(int size))
     * @param size Correspond à la longueur de la clef AES
     * @return Retourne une clef AES générée
     */
    @Override
    public KeyAES generatePublicKey(int size) {
        return generateKey(size);
    }

    /**
     * Génère une clef AES de longueur KEY_SIZE_MIN (AES est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey())
     * @return Retourne une clef générée
     */
    @Override
    public KeyAES generatePrivateKey() {
        return generateKey();
    }

    /**
     * Génère une clef AES de longueur size (AES est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey(int size))
     * @param size Correspond à la longueur de la clef AES
     * @return Retourne une clef AES générée
     */
    @Override
    public KeyAES generatePrivateKey(int size) {
        return generateKey(size);
    }
    
    /**
     * Chiffre les données
     * @param key Correspond à la clef de chiffrement AES
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées en AES
     */
    @Override
    public byte[] encrypt(Key key, byte[] datas) {
        if(key == null) throw new java.lang.NullPointerException("key is null.");
        if(datas == null) throw new java.lang.NullPointerException("datas is null.");
        
        java.security.Key generatedKey = new javax.crypto.spec.SecretKeySpec((key.toBytes() != null) ? key.toBytes() : key.toString().getBytes(), ALGORITHM);
        javax.crypto.Cipher chiper;
        try {
            chiper = javax.crypto.Cipher.getInstance(ALGORITHM);
            chiper.init(javax.crypto.Cipher.ENCRYPT_MODE, generatedKey);
            return chiper.doFinal(datas);
        } catch (java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException | java.security.InvalidKeyException | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException ex) {
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Déchiffre les données AES
     * @param key Correpsond à la clef de déchiffrement AES
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     */
    @Override
    public byte[] decrypt(Key key, byte[] datas) {
        if(key == null) throw new java.lang.NullPointerException("key is null.");
        if(datas == null) throw new java.lang.NullPointerException("datas is null.");
        
        try {
            java.security.Key generatedKey = new javax.crypto.spec.SecretKeySpec((key.toBytes() != null) ? key.toBytes() : key.toString().getBytes(), ALGORITHM);
            javax.crypto.Cipher chiper = javax.crypto.Cipher.getInstance(ALGORITHM);
            chiper.init(javax.crypto.Cipher.DECRYPT_MODE, generatedKey);
            return chiper.doFinal(datas);
        } catch (java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException | java.security.InvalidKeyException | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException ex) {
            java.util.logging.Logger.getLogger(AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Chiffre les données
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public byte[] encrypt(byte[] datas) {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Déchiffre les données
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    public byte[] decrypt(byte[] datas) {
        throw new UnsupportedOperationException("Method not supported."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
    
}