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
 * Cette classe d'énumération permet de détermine pour un type de chiffrage, s'il est symétrique, asymétrique ou s'il ne contient aucune clef
 * @author JasonPercus
 * @version 1.0
 */
public enum Type {
    
    
    
//CONSTANTS
    /**
     * Si le chiffrage ne contient aucune clef
     */
    NO_KEY,
    
    /**
     * Si le chiffrage est symétrique (il contient une seule clef de chiffrement et de déchiffrement)
     */
    SYMMETRIC,
    
    /**
     * Si le chiffrage est asymétrique (il contient une clef publique pour chiffrer et une clef privée pour déchiffrer)
     */
    ASYMMETRIC;
    
    
    
}