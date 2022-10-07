/*
 * Copyright (C) JasonPercus Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by JasonPercus, 08/2022
 */
package com.jasonpercus.encryption.md5;



import com.jasonpercus.util.Serializer;



/**
 * Cette classe permet d'obtenir le MD5 d'un objet, d'un flux, d'un fichier...
 * @author JasonPercus
 * @version 1.0
 */
public class MD5 implements java.io.Serializable, Comparable<MD5>, Cloneable {
    
    
    
//ATTRIBUT
    /**
     * Correspond à la valeur du MD5
     */
    private byte[] md5;

    
    
//CONSTRUCTORS
    /**
     * Crée un objet MD5
     */
    public MD5() {
        
    }
    
    /**
     * Crée un objet MD5
     * @param datas Correspond au tableau de bytes dont on cherche à calculer le MD5
     * @throws Exception S'il y a une erreur pendant le calcul 
     */
    public MD5(byte[] datas) throws Exception {
        this(new java.io.ByteArrayInputStream(datas));
    }
    
    /**
     * Crée un objet MD5
     * @param obj Correspond à l'objet dont on cherche à calculer le MD5
     * @throws Exception S'il y a une erreur pendant le calcul 
     */
    public MD5(java.io.Serializable obj) throws Exception {
        this(new java.io.ByteArrayInputStream(Serializer.getData(obj)));
    }
    
    /**
     * Crée un objet MD5
     * @param filename Correspond au nom du fichier dont on cherche à calculer le MD5
     * @throws Exception S'il y a une erreur pendant le calcul 
     */
    public MD5(String filename) throws Exception {
        this(new java.io.File(filename));
    }
    
    /**
     * Crée un objet MD5
     * @param file Correspond au fichier dont on cherche à calculer le MD5
     * @throws Exception S'il y a une erreur pendant le calcul 
     */
    public MD5(java.io.File file) throws Exception {
        this(new java.io.BufferedInputStream(new java.io.FileInputStream(file)));
    }
    
    /**
     * Crée un objet MD5
     * @param is Correspond au flux d'entré dont on cherche à calculer le MD5
     * @throws Exception S'il y a une erreur pendant le calcul 
     */
    public MD5(java.io.InputStream is) throws Exception {
        java.security.MessageDigest complete;
        byte[] buffer = new byte[1024];
        complete = java.security.MessageDigest.getInstance("MD5");
        int numRead;
        do {
            numRead = is.read(buffer);
            if (numRead > 0)
                complete.update(buffer, 0, numRead);
        } while (numRead != -1);
        is.close();
        this.md5 = complete.digest();
    }

    
    
//METHODES PUBLICS
    /**
     * Renvoie la valeur du MD5 sous la forme d'un tableau de bytes
     * @return Retourne la valeur du MD5 sous la forme d'un tableau de bytes
     */
    public byte[] toBytes() {
        return md5;
    }

    /**
     * Renvoie le hashCode de l'objet {@linkplain MD5}
     * @return Retourne le hashCode de l'objet {@linkplain MD5}
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + java.util.Arrays.hashCode(this.md5);
        return hash;
    }

    /**
     * Détermine si deux objets {@linkplain MD5} sont égaux ou pas
     * @param obj Correspond au second objet à comparer au courant
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
        final MD5 other = (MD5) obj;
        return java.util.Arrays.equals(this.md5, other.md5);
    }

    /**
     * Renvoie la valeur du MD5 sous la forme d'une chaîne de caractères
     * @return Retourne la valeur du MD5 sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        return toHex(this.md5);
    }

    /**
     * Compare deux objets {@linkplain MD5} entre eux
     * @param o Correspond au second objet à comparer au courant
     * @return Retourne le résultat de la comparaison
     */
    @Override
    public int compareTo(MD5 o) {
        if(o == null) return -1;
        return this.toString().compareTo(o.toString());
    }

    /**
     * Clone l'objet courant
     * @return Retourne une copie de l'objet courant
     * @throws CloneNotSupportedException S'il y a une erreur lors de la copie
     */
    @Override
    @SuppressWarnings("CloneDoesntCallSuperClone")
    protected Object clone() throws CloneNotSupportedException {
        byte[] toCopy = new byte[this.md5.length];
        System.arraycopy(this.md5, 0, toCopy, 0, this.md5.length);
        MD5 copy = new MD5();
        copy.md5 = toCopy;
        return copy;
    }
    
    
    
//METHODE PRIVATE STATIC
    /**
     * Converti un tableau de bytes en une chaîne hexadécimale
     * @param array Correspond au tableau de bytes à convertir
     * @return Retourne une chaîne hexadécimale
     */
    private static String toHex(byte[] array){
        StringBuilder builder = new StringBuilder("");

        for (int i = 0; i < array.length; i++) 
            builder.append(Integer.toString((array[i] & 0xff) + 0x100, 16).substring(1));
        
        return builder.toString();
    }
    
    
    
}