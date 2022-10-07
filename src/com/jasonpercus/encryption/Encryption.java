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
 * Cette classe abstraite permet de définir ce qu'une classe de chiffrage peut faire
 * @author Briguet
 * @version 1.0
 */
public abstract class Encryption {
    
    
    
//CONSTRUCTOR
    /**
     * Crée un objet Encryption par défaut
     */
    public Encryption() {
        
    }
    
    
    
//METHODES PUBLICS
    /**
     * Détermine quel est le type de dé/chiffrement (symétrique, asymétrique ou ne contient aucune clef)
     * @return Retourne le type de dé/chiffrement
     */
    public abstract Type getType();
    
    /**
     * Chiffre les données
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     */
    public abstract byte[] encrypt(byte[] datas);
    
    /**
     * Déchiffre les données
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     */
    public abstract byte[] decrypt(byte[] datas);
    
    /**
     * Chiffre un texte
     * @param chain Correspond au texte à chiffrer
     * @return Retourne le texte chiffré
     */
    public String encrypt(String chain){
        return new Base64().toString(encrypt(chain.getBytes()));
    }
    
    /**
     * Déchiffre un texte
     * @param chain Correspond au texte à déchiffrer
     * @return Retourne le texte déchiffré
     */
    public String decrypt(String chain){
        return new String(decrypt(new Base64().toBytes(chain)));
    }
    
    
    
}