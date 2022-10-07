/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption;



/**
 * Cette classe permet de représenter une clef de (dé)chiffrement
 * @author Briguet
 * @version 1.0
 */
public abstract class Key implements java.io.Serializable, Comparable<Key> {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>
    
    
    
//ATTRIBUTS
    /**
     * Correspond à la clef sous la forme d'un tableau binaire (si = null, alors keyString ne l'est pas)
     */
    private byte[] keyByte;
    
    /**
     * Correspond à la clef sous la forme d'une chaîne de caractères (si = null, alors keyByte ne l'est pas)
     */
    private String keyString;

    
    
//CONSTRUCTORS
    /**
     * Crée une clef vide
     */
    public Key() {
    }
    
    /**
     * Crée une clef
     * @param key Correspond à la clef String
     */
    public Key(String key) {
        this.keyString = key;
    }
    
    /**
     * Crée une clef
     * @param key Correspond à la clef byte[]
     */
    public Key(byte[] key) {
        this.keyByte = key;
    }

    
    
//METHODES PUBLICS
    /**
     * Retourne la clef sous la forme d'un tableau de bytes
     * @return Retourne la clef sous la forme d'un tableau de bytes
     */
    public byte[] getKey() {
        return keyByte;
    }

    /**
     * Modifie la clef
     * @param key Correspond à la nouvelle clef sous la forme d'un tableau de bytes
     */
    public void setKey(byte[] key) {
        this.keyByte = key;
    }

    /**
     * Modifie la clef
     * @param key Correspond à la nouvelle clef sous la forme d'une chaîne de caractères
     */
    public void setKey(String key) {
        this.keyString = key;
    }
    
    /**
     * Renvoie la clef sous la forme d'un tableau de byte
     * @return Retourne la clef sous la forme d'un tableau de byte
     */
    public byte[] toBytes(){
        return keyByte;
    }

    /**
     * Retourne la clef sous la forme d'une chaîne de caractères
     * @return Retourne la clef sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        return keyString;
    }

    /**
     * Renvoie le hashCode de la clef
     * @return Retourne le hashCode de la clef
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 29 * hash + java.util.Objects.hashCode(this.keyString);
        return hash;
    }

    /**
     * Renvoie true si otherKey est équivalent à l'objet courant, sinon false
     * @param otherKey Correspond à l'objet à comparer avec l'objet courant
     * @return Retourne true s'ils sont identiques sinon false
     */
    @Override
    public boolean equals(Object otherKey) {
        if (this == otherKey) {
            return true;
        }
        if (otherKey == null) {
            return false;
        }
        if (getClass() != otherKey.getClass()) {
            return false;
        }
        final Key other = (Key) otherKey;
        return java.util.Objects.equals(toString(), other.toString());
    }

    /**
     * Compare otherKey avec la clef courante
     * @param otherKey Correspond à la seconde clef à comparer avec celle courante
     * @return Retourne -1 si otherKey = null, sinon retourne la comparaison des chaînes String des deux clefs
     */
    @Override
    public int compareTo(Key otherKey) {
        if(otherKey == null) return -1;
        return keyString.compareTo(otherKey.keyString);
    }
    
    
    
}