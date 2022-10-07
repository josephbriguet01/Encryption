/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.aes;



import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.base64.Base64;



/**
 * Cette classe permet de représenter une clef de (dé)chiffrement AES
 * @author Briguet
 * @version 1.1
 */
public class KeyAES extends Key {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>

    
    
//CONSTRUCTORS
    /**
     * Crée une clef AES vide
     */
    public KeyAES() {
    }

    /**
     * Crée une clef AES
     * @param key Correspond à la clef String
     */
    public KeyAES(String key) {
        super(key);
    }

    /**
     * Crée une clef AES
     * @param key Correspond à la clef byte[]
     */
    public KeyAES(byte[] key) {
        super(key);
    }
    
    

//METHODES PUBLICS
    /**
     * Retourne la clef AES sous la forme d'un tableau de bytes
     * @return Retourne la clef AES sous la forme d'un tableau de bytes
     */
    @Override
    public byte[] getKey() {
        if(super.getKey() != null) return super.getKey();
        else return new Base64().decrypt(super.toString().getBytes());
    }
    
    /**
     * Modifie la clef AES
     * @param key Correspond à la nouvelle clef AES sous la forme d'un tableau de bytes
     */
    @Override
    public void setKey(byte[] key) {
        super.setKey((String) null);
        super.setKey(key);
    }

    /**
     * Modifie la clef AES
     * @param key Correspond à la nouvelle clef AES sous la forme d'une chaîne de caractères
     */
    @Override
    public void setKey(String key) {
        super.setKey((byte[]) null);
        super.setKey(key);
    }

    /**
     * Renvoie la clef AES sous la forme d'un tableau de byte
     * @return Retourne la clef AES sous la forme d'un tableau de byte
     */
    @Override
    public byte[] toBytes() {
        return getKey();
    }

    /**
     * Retourne la clef AES sous la forme d'une chaîne de caractères
     * @return Retourne la clef AES sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        if(super.getKey() == null) return super.toString();
        else return new String(new Base64().encrypt(super.getKey()));
    }

    /**
     * Compare otherKey avec la clef AES courante
     * @param otherKey Correspond à la seconde clef AES à comparer avec celle courante
     * @return Retourne -1 si otherKey = null, sinon retourne la comparaison des chaînes String des deux clefs AES
     */
    @Override
    public int compareTo(Key otherKey) {
        return toString().compareTo(otherKey.toString());
    }
    
    
    
}