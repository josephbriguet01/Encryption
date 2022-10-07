/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.rsa;



import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.KeyPublic;
import com.jasonpercus.encryption.base64.Base64;



/**
 * Cette classe permet de représenter une clef de chiffrement RSA
 * @author Briguet
 * @version 1.0
 */
public class KeyPublicRSA extends KeyPublic {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>

    
    
//CONSTRUCTORS
    /**
     * Crée une clef RSA publique vide
     */
    public KeyPublicRSA() {
    }

    /**
     * Crée une clef RSA publique
     * @param key Correspond à la clef String
     */
    public KeyPublicRSA(String key) {
        super(key);
    }

    /**
     * Crée une clef RSA publique
     * @param key Correspond à la clef byte[]
     */
    public KeyPublicRSA(byte[] key) {
        super(key);
    }
    
    
    
//METHODES PUBLICS
    /**
     * Retourne la clef RSA publique sous la forme d'un tableau de bytes
     * @return Retourne la clef RSA publique sous la forme d'un tableau de bytes
     */
    @Override
    public byte[] getKey() {
        if(super.getKey() != null) return super.getKey();
        else return new Base64().toBytes(super.toString());
    }

    /**
     * Modifie la clef RSA publique
     * @param key Correspond à la nouvelle clef RSA publique sous la forme d'un tableau de bytes
     */
    @Override
    public void setKey(byte[] key) {
        super.setKey((String) null);
        super.setKey(key);
    }

    /**
     * Modifie la clef RSA publique
     * @param key Correspond à la nouvelle clef RSA publique sous la forme d'une chaîne de caractères
     */
    @Override
    public void setKey(String key) {
        super.setKey((byte[]) null);
        super.setKey(key);
    }

    /**
     * Renvoie la clef RSA publique sous la forme d'un tableau de byte
     * @return Retourne la clef RSA publique sous la forme d'un tableau de byte
     */
    @Override
    public byte[] toBytes() {
        return getKey();
    }

    /**
     * Retourne la clef RSA publique sous la forme d'une chaîne de caractères
     * @return Retourne la clef RSA publique sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        if(super.getKey() == null) return super.toString();
        else return new Base64().toString(super.getKey());
    }

    /**
     * Compare otherKey avec la clef courante RSA publique
     * @param otherKey Correspond à la seconde clef RSA publique à comparer avec celle courante
     * @return Retourne -1 si otherKey = null, sinon retourne la comparaison des chaînes String des deux clefs RSA publique
     */
    @Override
    public int compareTo(Key otherKey) {
        return toString().compareTo(otherKey.toString());
    }
    
    
    
}