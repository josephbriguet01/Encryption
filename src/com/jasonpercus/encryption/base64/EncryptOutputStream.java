/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.base64;



/**
 * Un objet EncryptOutputStream obtient des octets de sortie chiffrés en base 64
 * @see java.io.OutputStream
 * @author JasonPercus
 * @version 1.0
 */
public class EncryptOutputStream extends com.jasonpercus.encryption.base.EncryptOutputStream {
    
    
    
//CONSTRUCTOR
    /**
     * Crée un flux EncryptOutputStream qui aura pour but de chiffrer un flux en base 64
     * @param output Correspond au flux chiffré
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public EncryptOutputStream(java.io.OutputStream output) throws java.io.IOException {
        super(output, new Base64());
    }
    
    
    
}