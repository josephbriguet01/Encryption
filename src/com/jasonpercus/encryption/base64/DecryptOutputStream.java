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
 * Un objet DecryptOutputStream obtient des octets de sortie déchiffrés de base 64 en base 256
 * @see java.io.OutputStream
 * @author JasonPercus
 * @version 1.0
 */
public class DecryptOutputStream extends com.jasonpercus.encryption.base.DecryptOutputStream {
    
    
    
//CONSTRUCTOR
    /**
     * Crée un flux DecryptOutputStream qui aura pour but de déchiffrer un flux base 64 en base 256
     * @param output Correspond au flux déchiffré
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public DecryptOutputStream(java.io.OutputStream output) throws java.io.IOException {
        super(output, new Base64());
    }
    
    
    
}