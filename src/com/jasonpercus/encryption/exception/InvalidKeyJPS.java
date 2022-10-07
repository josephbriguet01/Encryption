/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.exception;



import com.jasonpercus.encryption.jps.KeyJPS;



/**
 * Cette classe représente les exceptions liées à une mauvaise création de clef de dé/chiffrement
 * @see KeyJPS
 * @author Briguet
 * @version 1.0
 */
public class InvalidKeyJPS extends RuntimeException {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>

    
    
//CONSTRUCTOR
    /**
     * Crée une exception
     * @param message Correspond au message de l'exception
     */
    public InvalidKeyJPS(String message) {
        super(message);
    }
    
    
    
}