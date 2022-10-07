/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.exception;



/**
 * Cette classe abstraite représente les exceptions liées à la taille d'une clef
 * @author Briguet
 * @version 1.0
 */
public abstract class KeySizeException extends RuntimeException {
    
    
    
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
    public KeySizeException(String message) {
        super(message);
    }
    
    
    
}