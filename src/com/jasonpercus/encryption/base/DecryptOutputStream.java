/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.base;



/**
 * Un objet DecryptOutputStream obtient des octets de sortie déchiffrés en base 256
 * @see java.io.OutputStream
 * @author JasonPercus
 * @version 1.0
 */
public abstract class DecryptOutputStream extends java.io.OutputStream implements Comparable<DecryptOutputStream> {
    
    
    
//ATTRIBUT STATIC
    /**
     * Correspond au compteur d'id créant ainsi l'unicité de l'objet
     */
    private static int cptID = 0;
    
    
    
//ATTRIBUTS PRIVATES
    /**
     * Correspond à l'id du stream
     */
    private final int id;
    
    /**
     * Correspond à la base utilisée pour déchiffrer
     */
    private final Base base;
    
    /**
     * Correspond à l'output de sortie
     */
    private final java.io.OutputStream output;
    
    
    
//CONSTRUCTORS
    /**
     * Crée un flux DecryptOutputStream par défaut
     * @deprecated <div style="color: #D45B5B; font-style: italic">N'est pas utilisable.</div>
     */
    @Deprecated
    private DecryptOutputStream() {
        throw new UnsupportedOperationException("Method not supported.");
    }
    
    /**
     * Crée un flux DecryptOutputStream qui aura pour but de déchiffrer un flux en base 256
     * @param output Correspond au flux déchiffré
     * @param base Correspond à la base qui servira de déchiffrement (ex: s'il s'agit d'une base 64, alors le flux passera d'une base 64 à 256)
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public DecryptOutputStream(java.io.OutputStream output, Base base) throws java.io.IOException {
        this.id     = cptID++;
        this.base   = base;
        this.output = output;
    }

    
    
//METHODES PUBLICS
    /**
     * Écrit l'octet spécifié dans ce flux de sortie. Le contrat général pour write est qu'un octet est écrit dans le flux de sortie. L'octet à écrire est les huit bits de poids faible de l'argument b. Les 24 bits de poids fort de b sont ignorés
     * @param b Correspond au byte à écrire
     * @throws java.io.IOException Si une erreur d'E/S se produit. En particulier, un IOException peut être lancé si le flux de sortie a été fermé.
     */
    @Override
    public void write(int b) throws java.io.IOException {
        output.write(base.nextByteToDecrypt((byte) b));
    }

    /**
     * Ferme ce flux de sortie et libère toutes les ressources système associées à ce flux. Le contrat général de close est qu'il ferme le flux de sortie. Un flux fermé ne peut pas effectuer d'opérations de sortie et ne peut pas être rouvert
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    @Override
    public void close() throws java.io.IOException {
        output.flush();
        output.close();
        super.close();
    }

    /**
     * Vide ce flux de sortie et force l'écriture de tous les octets de sortie mis en mémoire tampon
     * @throws java.io.IOException Si une erreur d'E/S se produit
     * @deprecated <div style="color: #D45B5B; font-style: italic">N'a pas d'utilité particulière dans ce cas</div>
     */
    @Override
    @Deprecated
    public void flush() throws java.io.IOException {
        
    }

    /**
     * Renvoie le hashCode() du Stream
     * @return Retourne le hashCode() du Stream
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 83 * hash + this.id;
        return hash;
    }

    /**
     * Détermine si deux DecryptOutputStream sont identiques ou pas
     * @param obj Correspond au second objet DecryptOutputStream à comparer au courant
     * @return Retourne true s'ils sont identiques, sinon false
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DecryptOutputStream other = (DecryptOutputStream) obj;
        return this.id == other.id;
    }

    /**
     * Renvoie un DecryptOutputStream objet sous la forme d'une chaîne de caractères
     * @return Retourne un DecryptOutputStream objet sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        return getClass().getSimpleName() + "{decrypted using "+base.getClass().getSimpleName()+"}";
    }

    /**
     * Compare deux DecryptOutputStream
     * @param o Correspond au second DecryptOutputStream à comparer au courant
     * @return Retourne le résultat de la comparaison
     */
    @Override
    public int compareTo(DecryptOutputStream o) {
        if(this.id < o.id)
            return -1;
        else if (this.id > o.id)
            return 1;
        else
            return 0;
    }
    
    
    
}