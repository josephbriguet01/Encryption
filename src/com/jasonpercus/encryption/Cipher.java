/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption;



import com.jasonpercus.encryption.base64.Base64;



/**
 * Cette classe abstraite permet de définir ce qu'une classe de chiffrage peut faire en lien avec une ou des clefs
 * @author Briguet
 * @version 1.0
 */
public abstract class Cipher extends Encryption {
    
    
    
//CONSTRUCTOR
    /**
     * Crée un objet Cipher par défaut
     */
    public Cipher() {
        
    }
    
    
    
//METHODES PUBLICS
    /**
     * Génère une clef
     * @return Retourne une clef générée
     */
    public abstract Key generateKey();
    
    /**
     * Génère une clef de longueur size
     * @param size Correspond à la longueur de la clef
     * @return Retourne une clef générée
     */
    public abstract Key generateKey(int size);
    
    /**
     * Génère une clef de chiffrement (dite publique)
     * @return Retourne une clef publique
     */
    public abstract Key generatePublicKey();
    
    /**
     * Génère une clef de chiffrement (dite publique) de longueur size
     * @param size Correspond à la longueur de la clef
     * @return Retourne une clef publique
     */
    public abstract Key generatePublicKey(int size);
    
    /**
     * Génère une clef de déchiffrement (dite privée)
     * @return Retourne une clef privée
     */
    public abstract Key generatePrivateKey();
    
    /**
     * Génère une clef de déchiffrement (dite privée) de longueur size
     * @param size Correspond à la longueur de la clef
     * @return Retourne une clef privée
     */
    public abstract Key generatePrivateKey(int size);
    
    /**
     * Chiffre les données
     * @param key Correspond à la clef de chiffrement
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     */
    public abstract byte[] encrypt(Key key, byte[] datas);
    
    /**
     * Déchiffre les données
     * @param key Correpsond à la clef de déchiffrement
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     */
    public abstract byte[] decrypt(Key key, byte[] datas);
    
    /**
     * Chiffre un texte
     * @param key Correspond à la clef de chiffrement
     * @param chain Correspond au texte à chiffrer
     * @return Retourne le texte chiffré
     */
    public String encrypt(Key key, String chain) {
        if(chain == null) return null;
        byte[] encrypted = encrypt(key, chain.getBytes());
        if(encrypted == null) return null;
        return new Base64().toString(encrypted);
    }
    
    /**
     * Déchiffre un texte
     * @param key Correspond à la clef de déchiffrement
     * @param chain Correspond au texte à déchiffrer
     * @return Retourne le texte déchiffré
     */
    public String decrypt(Key key, String chain) {
        if(chain == null) return null;
        byte[] decoded = new Base64().toBytes(chain);
        if(decoded == null) return null;
        byte[] decrypted = decrypt(key, decoded);
        if(decrypted == null) return null;
        return new String(decrypted);
    }
    
    
    
}