/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 08/2020
 */
package com.jasonpercus.encryption.jps;



import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.base64.Base64;
import com.jasonpercus.encryption.exception.InvalidKeyJPS;



/**
 * Cette classe permet de créer une clef de dé/chiffrement JPS
 * @see JPS
 * @author Briguet
 * @version 1.0
 */
public final class KeyJPS extends Key {
    
    
    
    // <editor-fold defaultstate="collapsed" desc="SERIAL_VERSION_UID">
    /**
     * Correspond au numéro de série qui identifie le type de dé/sérialization utilisé pour l'objet
     */
    private static final long serialVersionUID = 1L;
    // </editor-fold>

    
    
//CONSTANTE
    /**
     * Correspond à la longueur minimale de la clef JPS
     */
    public static final int KEY_SIZE_MIN = 128;
    
    
    
//CONSTRUCTORS
    /**
     * Crée une clef vide
     */
    public KeyJPS() {
    }

    /**
     * Crée une clef
     * @param key Correspond à la clef String
     */
    public KeyJPS(String key) {
        super(key);
        super.setKey(new Base64().toBytes(key));
    }
    
    /**
     * Crée une clef
     * @param key Correspond à la clef byte[]
     */
    public KeyJPS(byte[] key) {
        super(key);
        super.setKey(new Base64().toString(key));
    }

    
    
//SETTERS
    /**
     * Modifie la clef
     * @param key Correspond à la nouvelle clef sous la forme d'un tableau de bytes
     */
    @Override
    public void setKey(byte[] key) {
        super.setKey(key);
        super.setKey(new Base64().toString(key));
    }
    
    /**
     * Modifie la clef
     * @param key Correspond à la nouvelle clef sous la forme d'une chaîne de caractères
     */
    @Override
    public void setKey(String key) {
        super.setKey(key);
        super.setKey(new Base64().toBytes(key));
    }
    
    
    
//METHODE PROTECTED
    /**
     * Vérifie si la clef est fonctionnelle
     * @return Retourne null si elle l'est, sinon renvoie une exception
     */
    protected InvalidKeyJPS isValid(){
        if(getKey() == null) return new InvalidKeyJPS("Data key is null !");
        if(getKey().length<KEY_SIZE_MIN) return new InvalidKeyJPS("The data size is too small ! The minimum length must be "+KEY_SIZE_MIN+" bytes");
        return null;
    }

    
    
    
//METHODES PUBLICS
    /**
     * Génère une clef aléatoire
     * @return Retourne une clef aléatoire générée
     */
    public static KeyJPS generate(){
        byte[] data = new byte[KEY_SIZE_MIN];
        new java.util.Random().nextBytes(data);
        return new KeyJPS(data);
    }
    
    /**
     * Génère une clef à partir d'un mot de passe
     * @param password Correspond au mot de passe qui génère la clef
     * @return Retourne la clef générée
     */
    public static KeyJPS generate(String password){
        if(password == null) throw new java.lang.NullPointerException("Password is null !");
        if(password.isEmpty()) throw new InvalidKeyJPS("Password is empty !");
        String md51 = getMD5(password);
        String md52 = getMD5(md51);
        String md53 = getMD5(md52);
        String md54 = getMD5(md53);
        String md5 = "";
        for(int i=0;i<md51.length();i++)
            md5 += ""+md54.charAt(i)+md52.charAt(i)+md51.charAt(i)+md53.charAt(i);
        return new KeyJPS(mirror(md5.getBytes()));
    }
    
    
    
//METHODES PRIVATES
    /**
     * Renvoie le hash MD5 d'une chaîne de caractère
     * @param text Correspond au text dont on cherche le hash
     * @return Retourne le hash de la chaîne de caractère
     */
    @SuppressWarnings("CallToPrintStackTrace")
    private static String getMD5(String text){
        try {
            java.security.MessageDigest m = java.security.MessageDigest.getInstance("MD5");
            m.reset();
            m.update(text.getBytes());
            byte[] digest = m.digest();
            java.math.BigInteger bigInt = new java.math.BigInteger(1,digest);
            String hashtext = bigInt.toString(16);
            while(hashtext.length() < 32 ){
                hashtext = "0"+hashtext;
            }
            return hashtext.substring(0, 32).toUpperCase();
        } catch (java.security.NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * Retourne une liste de bytes
     * @param datas Correspond à la liste à retourner
     * @return Retourne une liste de bytes
     */
    private static byte[] mirror(byte[] datas){
        byte[] bs   = new byte[datas.length];
        int cpt     = 0;
        
        for(int i=datas.length-1;i>-1;i--)
            bs[cpt++] = datas[i];
        
        return bs;
    }
    
    
    
}