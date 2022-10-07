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
 * Cette classe permet de représenter une clef de déchiffrement
 * @author Briguet
 * @version 1.0
 */
public abstract class KeyPrivate extends Key {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>

    
    
//CONSTRUCTORS
    /**
     * Crée une clef vide
     */
    public KeyPrivate() {
    }

    /**
     * Crée une clef
     * @param key Correspond à la clef String
     */
    public KeyPrivate(String key) {
        super(key);
    }

    /**
     * Crée une clef
     * @param key Correspond à la clef byte[]
     */
    public KeyPrivate(byte[] key) {
        super(key);
    }
    
    
    
}