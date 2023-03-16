/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 08/2020
 */
package com.jasonpercus.encryption.jps;



import com.jasonpercus.encryption.Cipher;
import com.jasonpercus.encryption.Key;
import com.jasonpercus.encryption.Type;
import com.jasonpercus.encryption.exception.InvalidKeyJPS;



/**
 * Cette classe permet de dé/chiffrer des données avec l'algoithme JPS
 * @see KeyJPS
 * @author Briguet
 * @version 1.0
 */
public class JPS extends Cipher {


    
//CONSTANTES
    private final static byte[] MOTIF_FIRST0 = {6,3,0,7,1,5,2,4};
    private final static byte[] MOTIF_FIRST1 = {6,3,0,1,5,2,4};
    private final static byte[] MOTIF_FIRST2 = {3,0,1,5,2,4};
    private final static byte[] MOTIF_FIRST3 = {3,0,4,2,1};
    private final static byte[] MOTIF_FIRST4 = {3,0,2,1};
    private final static byte[] MOTIF_FIRST5 = {2,0,1};
    private final static byte[] MOTIF_FIRST6 = {1,0};
    private final static byte[] MOTIF_REVERSE_FIRST0 = {4,2,5,1,7,0,3,6};
    private final static byte[] MOTIF_REVERSE_FIRST1 =   {4,2,5,1,0,3,6};
    private final static byte[] MOTIF_REVERSE_FIRST2 =     {4,2,5,1,0,3};
    private final static byte[] MOTIF_REVERSE_FIRST3 =       {1,2,4,0,3};
    private final static byte[] MOTIF_REVERSE_FIRST4 =         {1,2,0,3};
    private final static byte[] MOTIF_REVERSE_FIRST5 =           {1,0,2};
    private final static byte[] MOTIF_REVERSE_FIRST6 =             {0,1};
    private final static byte[] MOTIF_SECOND0 = {3,1,6,7,2,4,0,5};
    private final static byte[] MOTIF_SECOND1 = {3,1,6,2,4,0,5};
    private final static byte[] MOTIF_SECOND2 = {3,1,2,4,0,5};
    private final static byte[] MOTIF_SECOND3 = {3,1,2,4,0};
    private final static byte[] MOTIF_SECOND4 = {3,1,2,0};
    private final static byte[] MOTIF_SECOND5 = {1,2,0};
    private final static byte[] MOTIF_SECOND6 = {1,0};
    private final static byte[] MOTIF_REVERSE_SECOND0 = {4,6,1,0,5,3,7,2};
    private final static byte[] MOTIF_REVERSE_SECOND1 =   {3,5,0,4,2,6,1};
    private final static byte[] MOTIF_REVERSE_SECOND2 =     {2,4,3,1,5,0};
    private final static byte[] MOTIF_REVERSE_SECOND3 =       {1,3,2,0,4};
    private final static byte[] MOTIF_REVERSE_SECOND4 =         {0,2,1,3};
    private final static byte[] MOTIF_REVERSE_SECOND5 =           {1,0,2};
    private final static byte[] MOTIF_REVERSE_SECOND6 =             {0,1};
    private final static byte[] ENCRYPT_MATRIX = {-1, 43, -53, -9, -40, -91, -34, -50, -43, 41, 68, 33, 15, -32, 42, -61, 88, 90, 72, -75, 2, 38, 127, 31, 14, 102, 115, 107, 78, -81, 106, -31, -41, -16, -101, 109, 95, 99, 122, -12, -4, 53, 116, -111, 108, -85, 21, -10, -6, 1, -126, -44, -15, -103, 22, -94, 73, -119, -52, 54, -36, -65, 100, 8, -57, -25, 13, 112, -26, -60, -83, -51, -117, 16, -18, -46, -120, -108, -114, -90, 79, -125, -54, 74, -3, -127, -104, 60, 12, 89, 97, -128, 50, -79, -47, -80, -78, 32, -11, 64, -109, -30, 69, -74, 92, 26, 66, 19, 82, -70, 81, 65, 29, -102, 18, 91, 62, -7, -59, 85, 25, 96, -14, -27, -67, -124, -58, 28, -21, -28, 120, 0, -77, 56, -45, -56, 24, -76, -33, -88, 118, 11, 113, -123, 23, 70, -48, -22, -35, -8, -62, -63, -118, 126, 51, 6, 7, -38, 61, 80, -23, 30, 87, 40, 105, -92, -72, 34, 39, 103, -105, -73, -100, -71, 125, -24, -112, 10, -82, 84, 86, 101, -19, -115, -68, 4, 121, -86, -116, -29, 77, 46, 93, 76, -107, 67, -110, 57, 124, 9, 119, 110, -20, 111, 94, -13, 52, -96, 98, 59, -37, 17, 55, -69, 5, 75, 36, 83, -106, -87, 44, 104, 27, -42, 49, -97, -95, 37, -39, 45, -84, 114, -89, -55, -121, -122, -99, 117, -64, -113, 3, 35, 63, -5, -49, 58, -66, 48, -93, 71, 123, 20, -98, -2, -17, 47};
    private final static byte[] DECRYPT_MATRIX = {-37, -43, -78, -47, -3, 15, 107, 106, -52, -71, 24, -56, 60, 55, -50, 111, 48, -85, 68, -28, -51, 66, 90, 42, -42, -75, -15, -94, 44, 108, 124, 97, 79, 98, -73, 120, 37, -123, -49, 104, 11, 91, 59, -83, 102, -58, 50, -99, -33, -35, -32, 4, 9, -109, -25, 43, 38, 45, -19, 85, 56, -4, 118, -67, 110, 23, 22, -113, -59, -10, -2, -64, 7, 105, -46, -126, -70, -57, -121, 116, 18, -34, -53, 6, -77, -120, 95, -96, -124, 100, 29, 82, -68, 20, -122, 10, -115, -97, -27, 61, 1, -5, -60, -63, 47, 32, 19, 0, 74, 54, -54, 126, -95, -76, -6, 77, -89, -30, -81, -125, 21, -11, -80, 115, -88, -44, 125, -128, 3, -79, -108, 112, 57, 86, 27, 28, -65, 71, 49, 13, -40, -62, -104, -116, -55, 83, -14, -21, 123, -82, -74, 16, 8, -8, -23, 94, -1, -16, 33, -105, -31, -117, 39, 113, 88, 99, -107, 40, 35, -119, -114, -127, 92, 101, 63, 127, 119, 96, -36, 26, 78, -87, -69, 84, 5, 69, 117, 81, -41, 30, -12, 114, -29, -17, -22, 67, -118, -26, 17, 121, -110, -72, -45, 87, 65, 62, -100, -48, 31, -18, -20, 89, 51, -9, 52, 34, -112, -39, -111, -13, -24, 64, 76, -92, -7, -38, 80, -91, -66, 53, -103, 41, 93, 36, -98, -101, -84, -93, 73, 75, -61, 14, 103, -102, -86, 109, 12, 72, 2, 58, -90, 122, 70, 46, 25, -106};
    
    /**
     * Sépare le salt avec des données trop petite
     */
    private final static byte[] SEPARATOR = {80, -122, 53, 1, 44, -72, 22, 68, -47, 32, 118, -96};
    
    /**
     * Correspond à la longueur minimale que doit avoir les données, sans quoi le séparateur et un salt est appliqué
     */
    private final static int MIN = 256;

    
    
//CONSTRUCTOR
    /**
     * Correspond au constructeur par défaut
     */
    public JPS() {
    }

    
    
    
//METHODES PUBLICS
    /**
     * Renvoie le type {@link Type#SYMMETRIC}
     * @return Retourne le type {@link Type#SYMMETRIC}
     */
    @Override
    public Type getType() {
        return Type.SYMMETRIC;
    }
    
    /**
     * Génère une clef aléatoire
     * @return Retourne une clef aléatoire générée
     */
    @Override
    public Key generateKey() {
        return KeyJPS.generate();
    }
    
    /**
     * Génère une clef à partir d'un mot de passe
     * @param password Correspond au mot de passe qui génère la clef
     * @return Retourne la clef générée
     */
    public static KeyJPS generate(String password){
        return KeyJPS.generate(password);
    }

    /**
     * Génère une clef aléatoire de taille n
     * @param size Correspond à la taille de la future clef
     * @return Retourne la clef générée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    @Deprecated
    public Key generateKey(int size) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Génère une clef JPS (JPS est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey())
     * @return Retourne une clef générée
     */
    @Override
    public Key generatePublicKey() {
        return generateKey();
    }

    /**
     * Génère une clef JPS de taille n
     * @param size Correspond à la taille de la future clef
     * @return Retourne la clef générée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    @Deprecated
    public Key generatePublicKey(int size) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Génère une clef JPS (JPS est un chiffrage symétrique, donc il n'y a pas de clef public ou privée. C'est pourquoi cette méthode appelle generateKey())
     * @return Retourne une clef générée
     */
    @Override
    public Key generatePrivateKey() {
        return generateKey();
    }

    /**
     * Génère une clef JPS de taille n
     * @param size Correspond à la taille de la future clef
     * @return Retourne la clef générée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    @Deprecated
    public Key generatePrivateKey(int size) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Chiffre des données
     * @param key Correspond à la clef de chiffrement
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     */
    @Override
    public byte[] encrypt(Key key, byte[] datas) {
        if(key != null){
            if(key instanceof KeyJPS){
                KeyJPS k = (KeyJPS) key;
                InvalidKeyJPS exception = k.isValid();
                if(exception == null){
                    if(datas.length < MIN){
                        byte[] random = new byte[MIN - datas.length];
                        new java.util.Random().nextBytes(random);
                        datas = concat(datas, concat(SEPARATOR, random));
                    }
                    byte[] result = datas;
                    for(int i=0;i<10;i++)
                        result = encrypt(result, prepareKey(k));
                    return result;
                }else throw exception;
            }else throw new java.lang.ClassCastException("key in not an instance of KeyJPS !");
        }else throw new java.lang.NullPointerException("key = null !");
    }

    /**
     * Déchiffre les données
     * @param key Correspond à la clef de déchiffrement
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     */
    @Override
    public byte[] decrypt(Key key, byte[] datas) {
        if(key != null){
            if(key instanceof KeyJPS){
                KeyJPS k = (KeyJPS) key;
                InvalidKeyJPS exception = k.isValid();
                if(exception == null){
                    byte[] response = datas;
                    for(int i=0;i<10;i++)
                        response = decrypt(response, prepareKey(k));
                    if(response.length == (SEPARATOR.length + MIN)){
                        java.util.List<byte[]> spliter = split(SEPARATOR, response);
                        if(spliter.isEmpty()) return new byte[0];
                        if(spliter.size() == 1) return spliter.get(0);
                        if(spliter.size() == 2) return spliter.get(0);
                    }
                    return response;
                }else throw exception;
            }else throw new java.lang.ClassCastException("key in not an instance of KeyJPS !");
        }else throw new java.lang.NullPointerException("key = null !");
    }

    /**
     * Chiffre les données
     * @param datas Correspond aux données à chiffrer
     * @return Retourne les données chiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    @Deprecated
    public byte[] encrypt(byte[] datas) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Déchiffre les données
     * @param datas Correspond aux données à déchiffrer
     * @return Retourne les données déchiffrées
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée dans ce contexte. Malgré tout si elle devait l'être par inadvertance, celle-ci lèvera une exception.</div>
     */
    @Override
    @Deprecated
    public byte[] decrypt(byte[] datas) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    
    
//METHODES PRIVATES STATICS
    /**
     * Prépare la clef pour pouvoir réaliser le dé/chiffrage
     * @param key Correspond à la clef de dé/chiffrement
     * @return Retourne la data préparée de la clef splitée en bloc de 8 bytes
     */
    private static java.util.List<byte[]> prepareKey(KeyJPS key){
        
        byte[] datas                    = key.getKey();
        byte[] beforeKey                = null;
        java.util.List<byte[]> bytes    = new java.util.ArrayList<>();
        
        int entier  = datas.length/8;
        int rest    = datas.length%8;
        int cpt     = 0;
        int pointer = 0;
        
        byte[] bs   = (pointer<entier) ? new byte[8] : new byte[rest];
        
        for(int i=datas.length-1;i>-1;i--){
            bs[cpt++] = datas[i];
            if(cpt>=8){
                cpt = 0;
                bytes.add(beforeKey = add(motifEncryptSecond(motifEncryptReverseFirst(bs)), beforeKey));
                pointer++;
                if(pointer<entier)
                    bs = new byte[8];
                else if(rest>0)
                    bs = new byte[rest];
            }
        }
        
        if(rest>0)
            bytes.add(add(motifEncryptSecond(motifEncryptReverseFirst(bs)), beforeKey));
        
        return bytes;
    }
    
    /**
     * Chiffre les datas
     * @param datas Correspond aux datas à chiffrer
     * @param preparedKey Correspond à la clef préparée
     * @return Retourne les données chiffrées
     */
    private static byte[] encrypt(byte[] datas, java.util.List<byte[]> preparedKey){
        byte[] before                   = null;
        java.util.List<byte[]> bytes    = new java.util.ArrayList<>();
        
        int entier  = datas.length/8;
        int rest    = datas.length%8;
        int cpt     = 0;
        int pointer = 0;
        
        byte[] bs   = (pointer<entier) ? new byte[8] : new byte[rest];
        
        for(int i=datas.length-1;i>-1;i--){
            bs[cpt++] = datas[i];
            if(cpt>=8){
                cpt = 0;
                bytes.add(before = minusAndReplace(motifEncryptReverseSecond(add(motifEncryptReverseFirst(de_fusionBytes(bs)), preparedKey.get(pointer%8))), before));
                pointer++;
                if(pointer<entier)
                    bs = new byte[8];
                else if(rest>0)
                    bs = new byte[rest];
            }
        }
        if(rest>0)
            bytes.add(minusAndReplace(motifEncryptReverseSecond(add(motifEncryptReverseFirst(bs), preparedKey.get(pointer%8))), before));
        
        return encryptReplaceByDivisible(joinAndMirror(bytes));
    }
    
    /**
     * Déchiffre les datas
     * @param datas Correspond aux datas à déchiffrer
     * @param preparedKey Correspond à la clef préparée
     * @return Retourne les données déchiffrées
     */
    private static byte[] decrypt(byte[] datas, java.util.List<byte[]> preparedKey){
        
        byte[] before                   = null;
        java.util.List<byte[]> bytes    = new java.util.ArrayList<>();
        
        datas = decryptReplaceByDivisible(datas);
        
        int entier  = datas.length/8;
        int rest    = datas.length%8;
        int cpt     = 0;
        int pointer = 0;
        
        byte[] bs   = (pointer<entier) ? new byte[8] : new byte[rest];
        
        for(int i=datas.length-1;i>-1;i--){
            bs[cpt++] = datas[i];
            if(cpt>=8){
                cpt = 0;
                byte[] val = bs;
                bs = de_fusionBytes(motifDecryptFirst(mirrorMinus(motifDecryptSecond(mirrorReplaceAndAdd(bs, before)), preparedKey.get(pointer%8))));
                before = val;
                pointer++;
                bytes.add(bs);
                if(pointer<entier)
                    bs = new byte[8];
                else if(rest>0)
                    bs = new byte[rest];
            }
        }
        
        if(rest>0)
            bytes.add(motifDecryptFirst(mirrorMinus(motifDecryptSecond(mirrorReplaceAndAdd(bs, before)), preparedKey.get(pointer%8))));
        
        return joinAndMirror(bytes);
    }
    
    /**
     * Fusionne toutes les listes de tableaux de bytes et retourne la liste final de bytes
     * @param datas Correspond à la liste de tableaux de bytes
     * @return Retourne une liste de bytes retournée
     */
    private static byte[] joinAndMirror(java.util.List<byte[]> datas){
        int size;
        int sizeDatas = datas.size();
        switch (sizeDatas) {
            case 0:
                size = 0;
                break;
            case 1:
                size = datas.get(0).length;
                break;
            default:
                size = ((sizeDatas-1) * 8) + datas.get(sizeDatas -1).length;
                break;
        }
        int cpt = 0;
        byte[] response = new byte[size];
        for(int j=datas.size()-1;j>-1;j--){
            byte[] bs = datas.get(j);
            for(int i=bs.length-1;i>-1;i--){
                response[cpt] = bs[i];
                cpt++;
            }
        }
        return response;
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
    
    /**
     * Enchiffre par positionnent les bytes selon l'ordre d'un motif inversé
     * @param blocDatas Correspond aux données à repositionner
     * @return Retourne les données repositionnées
     */
    @SuppressWarnings("null")
    private static byte[] motifEncryptReverseFirst(byte[] blocDatas){
        byte[] motif = null;
        
        if(blocDatas.length == 8) motif = MOTIF_REVERSE_FIRST0;
        if(blocDatas.length == 7) motif = MOTIF_REVERSE_FIRST1;
        if(blocDatas.length == 6) motif = MOTIF_REVERSE_FIRST2;
        if(blocDatas.length == 5) motif = MOTIF_REVERSE_FIRST3;
        if(blocDatas.length == 4) motif = MOTIF_REVERSE_FIRST4;
        if(blocDatas.length == 3) motif = MOTIF_REVERSE_FIRST5;
        if(blocDatas.length == 2) motif = MOTIF_REVERSE_FIRST6;
        if(blocDatas.length == 0 || blocDatas.length == 1) return blocDatas;
        
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<motif.length;i++)
            response[indexOf(motif, i)] = blocDatas[i];
        
        return response;
    }
    
    /**
     * Déchiffre par positionnent les bytes selon l'ordre d'un motif
     * @param blocDatas Correspond aux données à repositionner
     * @return Retourne les données repositionnées
     */
    private static byte[] motifDecryptFirst(byte[] blocDatas){
        byte[] motif = null;
        
        if(blocDatas.length == 8) motif = MOTIF_FIRST0;
        if(blocDatas.length == 7) motif = MOTIF_FIRST1;
        if(blocDatas.length == 6) motif = MOTIF_FIRST2;
        if(blocDatas.length == 5) motif = MOTIF_FIRST3;
        if(blocDatas.length == 4) motif = MOTIF_FIRST4;
        if(blocDatas.length == 3) motif = MOTIF_FIRST5;
        if(blocDatas.length == 2) motif = MOTIF_FIRST6;
        if(blocDatas.length == 0 || blocDatas.length == 1) return blocDatas;
        
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[motif[i]] = blocDatas[i];
        
        return response;
    }
    
    /**
     * Enchiffre par positionnent les bytes selon l'ordre d'un motif
     * @param blocDatas Correspond aux données à repositionner
     * @return Retourne les données repositionnées
     */
    private static byte[] motifEncryptSecond(byte[] blocDatas){
        byte[] motif = null;
        
        if(blocDatas.length == 8) motif = MOTIF_SECOND0;
        if(blocDatas.length == 7) motif = MOTIF_SECOND1;
        if(blocDatas.length == 6) motif = MOTIF_SECOND2;
        if(blocDatas.length == 5) motif = MOTIF_SECOND3;
        if(blocDatas.length == 4) motif = MOTIF_SECOND4;
        if(blocDatas.length == 3) motif = MOTIF_SECOND5;
        if(blocDatas.length == 2) motif = MOTIF_SECOND6;
        if(blocDatas.length == 0 || blocDatas.length == 1) return blocDatas;
        
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[motif[i]] = blocDatas[i];
        
        return response;
    }
    
    /**
     * Enchiffre par positionnent les bytes selon l'ordre d'un motif inversé
     * @param blocDatas Correspond aux données à repositionner
     * @return Retourne les données repositionnées
     */
    private static byte[] motifEncryptReverseSecond(byte[] blocDatas){
        byte[] motif = null;
        
        if(blocDatas.length == 8) motif = MOTIF_REVERSE_SECOND0;
        if(blocDatas.length == 7) motif = MOTIF_REVERSE_SECOND1;
        if(blocDatas.length == 6) motif = MOTIF_REVERSE_SECOND2;
        if(blocDatas.length == 5) motif = MOTIF_REVERSE_SECOND3;
        if(blocDatas.length == 4) motif = MOTIF_REVERSE_SECOND4;
        if(blocDatas.length == 3) motif = MOTIF_REVERSE_SECOND5;
        if(blocDatas.length == 2) motif = MOTIF_REVERSE_SECOND6;
        if(blocDatas.length == 0 || blocDatas.length == 1) return blocDatas;

        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[motif[i]] = blocDatas[i];
            
        return response;
    }
    
    /**
     * Déchiffre par positionnent les bytes selon l'ordre d'un motif
     * @param blocDatas Correspond aux données à repositionner
     * @return Retourne les données repositionnées
     */
    @SuppressWarnings("null")
    private static byte[] motifDecryptSecond(byte[] blocDatas){
        byte[] motif = null;
        
        if(blocDatas.length == 8) motif = MOTIF_SECOND0;
        if(blocDatas.length == 7) motif = MOTIF_SECOND1;
        if(blocDatas.length == 6) motif = MOTIF_SECOND2;
        if(blocDatas.length == 5) motif = MOTIF_SECOND3;
        if(blocDatas.length == 4) motif = MOTIF_SECOND4;
        if(blocDatas.length == 3) motif = MOTIF_SECOND5;
        if(blocDatas.length == 2) motif = MOTIF_SECOND6;
        if(blocDatas.length == 0 || blocDatas.length == 1) return blocDatas;
        
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<motif.length;i++)
            response[indexOf(motif, i)] = blocDatas[i];
        
        return response;
    }
    
    /**
     * Renvoie l'index d'une valeur dans un tableau de bytes
     * @param motif Correspond au tableau de bytes dont on cherche une valeur
     * @param value Correspond à la valeur à rechercher
     * @return Retourne l'index de la valeur trouvée
     */
    private static int indexOf(byte[] motif, int value){
        for(int i=0;i<motif.length;i++){
            if(motif[i] == value)
                return i;
        }
        return -1;
    }
    
    /**
     * Aditionne deux bytes entre-eux et repositionne le résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param b1 Correspond au premier byte de l'opération
     * @param b2 Correspond au second byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte add(byte b1, byte b2){
        return recentre(b1 + b2);
    }
    
    /**
     * Soustrait deux bytes entre-eux et repositionne le résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param b1 Correspond au premier byte de l'opération
     * @param b2 Correspond au second byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte minus(byte b1, byte b2){
        return recentre(b1 - b2);
    }
    
    /**
     * Additionne deux tableaux de bytes entre-eux et repositionne chaque byte du tableau résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param blocDatas Correspond au premier tableau de byte de l'opération
     * @param blocKey Correspond au second tableau de byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte[] add(byte[] blocDatas, byte[] blocKey){
        if(blocKey == null) return blocDatas;
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[i] = add(blocDatas[i], blocKey[i]);
        
        return response;
    }
    
    /**
     * Additionne deux tableaux de bytes entre-eux et repositionne chaque byte du tableau résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param blocDatas Correspond au premier tableau de byte de l'opération
     * @param blocKey Correspond au second tableau de byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte[] mirrorReplaceAndAdd(byte[] blocDatas, byte[] blocKey){
        if(blocKey == null) return mirror(blocDatas);
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[blocDatas.length-1-i] = add(decryptReplace(blocDatas[i]), blocKey[i]);
        
        return response;
    }
    
    /**
     * Soustrait deux tableaux de bytes entre-eux et repositionne chaque byte du tableau résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param blocDatas Correspond au premier tableau de byte de l'opération
     * @param blocKey Correspond au second tableau de byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte[] mirrorMinus(byte[] blocDatas, byte[] blocKey){
        if(blocKey == null) return mirror(blocDatas);
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[blocDatas.length-1-i] = minus(blocDatas[i], blocKey[i]);
        
        return response;
    }
        
    /**
     * Soustrait deux tableaux de bytes entre-eux et repositionne chaque byte du tableau résultat pour ne pas être à l'extérieur des limites d'un byte
     * @param blocDatas Correspond au premier tableau de byte de l'opération
     * @param blocKey Correspond au second tableau de byte de l'opération
     * @return Retourne le résultat de l'opération
     */
    private static byte[] minusAndReplace(byte[] blocDatas, byte[] blocKey){
        if(blocKey == null) return blocDatas;
        byte[] response = new byte[blocDatas.length];
        
        for(int i=0;i<blocDatas.length;i++)
            response[i] = encryptReplace(minus(blocDatas[i], blocKey[i]));
        
        return response;
    }
    
    /**
     * Recentre un byte pour que celui-ci ne soit pas être à l'extérieur des limites d'un byte
     * @param res Correspond à la valeur à replacer dans les limites d'un byte
     * @return Retourne un byte recentré
     */
    private static byte recentre(int res){
        if(res>Byte.MAX_VALUE) return (byte) (res - 2 * Byte.MIN_VALUE);
        if(res<Byte.MIN_VALUE) return (byte) (res + (-2 * Byte.MIN_VALUE));
        return (byte) res;
    }
    
    /**
     * Remplace un byte par un autre
     * @param b Correspond au byte qui doit être remplacé
     * @return Retourne un autre byte
     */
    private static byte encryptReplace(byte b){
        return ENCRYPT_MATRIX[b+128];
    }
    
    /**
     * Remplace un byte par un autre
     * @param b Correspond au byte qui doit être remplacé
     * @return Retourne un autre byte
     */
    private static byte decryptReplace(byte b){
        return DECRYPT_MATRIX[b+128];
    }
    
    /**
     * Concatène deux tableaux de bytes
     * @param array1 Correspond au premier tableau à concaténer
     * @param array2 Correspond au second tableau à concaténer
     * @return Retourne un tableau concaténé
     */
    private static byte[] concat(byte[] array1, byte[] array2){
        byte[] result = new byte[array1.length+array2.length];
  
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        
        return result;
    }
    
    /**
     * Renvoie true si le pattern a été trouvé dans le tableau de byte à la position donnée
     * @param pattern Correspond au pattern qui est recherché dans le tableau
     * @param input Correspond au tableau de bytes où l'on cherche le pattern
     * @param pos Correspond à la position où l'on recherche le pattern
     * @return Retourne true si le pattern a été trouvé sinon false
     */
    private static boolean isMatch(byte[] pattern, byte[] input, int pos) {
        for(int i=0; i< pattern.length; i++) {
            if(pattern[i] != input[pos+i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Renvoie un split d'un tableau de bytes
     * @param pattern Correspond au pattern qui split le tableau
     * @param input Correspond au tableau qui va être splité
     * @return Retourne une liste de tableau
     */
    private static java.util.List<byte[]> split(byte[] pattern, byte[] input) {
        java.util.List<byte[]> l = new java.util.LinkedList<>();
        int blockStart = 0;
        for(int i=0; i<input.length; i++) {
           if(isMatch(pattern,input,i)) {
              l.add(java.util.Arrays.copyOfRange(input, blockStart, i));
              blockStart = i+pattern.length;
              i = blockStart;
           }
        }
        l.add(java.util.Arrays.copyOfRange(input, blockStart, input.length ));
        return l;
    }
    
    /**
     * Renvoie le quotient et la taille des sous blocs
     * @param array Correspond à la liste des données à dé/chiffrer
     * @return Retourne le quotient dans int[0] et la taille des sous blocs dans int[1]
     */
    private static int[] quotientAndSize(byte[] array){
        int quotient = 0;
        for (int i = array.length - 1; i > 0; i--) {
            if (array.length % i == 0) {
                quotient = i;
                break;
            }
        }
        int sizePacket = array.length/quotient;
        return new int[]{quotient, sizePacket};
    }
    
    /**
     * Chiffre à partir du quotient maximum et de la taille des sous blocs de la chaîne
     * @param array Correspond à la chaîne à chiffrer
     * @return Renvoie la chaîne chiffrée
     */
    private static byte[] encryptReplaceByDivisible(byte[] array){
        int[] quotientAndSize = quotientAndSize(array);
        int quotient = quotientAndSize[0];
        int sizePacket = quotientAndSize[1];
        if (quotient > 1) {
            int cpt2 = 0;
            byte[] resFin = new byte[array.length];
            for (int j = 0; j < quotient; j++) {
                for (int i = 0; i < sizePacket; i++)
                    resFin[cpt2++] = array[quotient * i + j];
            }
            return resFin;
        } else
            return array;
    }
    
    /**
     * Déchiffre à partir du quotient maximum et de la taille des sous blocs de la chaîne
     * @param array Correspond à la chaîne à déchiffrer
     * @return Renvoie la chaîne déchiffrée
     */
    private static byte[] decryptReplaceByDivisible(byte[] array){
        int[] quotientAndSize = quotientAndSize(array);
        int quotient = quotientAndSize[0];
        int sizePacket = quotientAndSize[1];
        if (quotient > 1) {
            int cpt2 = 0;
            byte[] resFin = new byte[array.length];
            for (int j = 0; j < quotient; j++) {
                for (int i = 0; i < sizePacket; i++)
                    resFin[quotient * i + j] = array[cpt2++];
            }
            return resFin;
        } else
            return array;
    }
    
    /**
     * Fusionne ou défusionne le bit[0] de chaque bit pour reformer un byte, puis le bit[1] pour reformer un autre byte...
     * @param bloc Correspond à la liste des 8 bytes qui vont être dé/fusionnée
     * @return Retourne le bloc de bytes dé/fusionnné
     */
    private static byte[] de_fusionBytes(byte[] bloc){
        boolean[] b1 = byteToBoolArr(bloc[0]);
        boolean[] b2 = byteToBoolArr(bloc[1]);
        boolean[] b3 = byteToBoolArr(bloc[2]);
        boolean[] b4 = byteToBoolArr(bloc[3]);
        boolean[] b5 = byteToBoolArr(bloc[4]);
        boolean[] b6 = byteToBoolArr(bloc[5]);
        boolean[] b7 = byteToBoolArr(bloc[6]);
        boolean[] b8 = byteToBoolArr(bloc[7]);
        
        
        for(int i=0;i<bloc.length;i++){
            bloc[i] = boolArrToByte(new boolean[]{b1[i], b2[i], b3[i], b4[i], b5[i], b6[i], b7[i], b8[i]});
        }
        return bloc;
    }
    
    /**
     * Transforme un byte en une liste de 8 boolean
     * @param b Correspond au byte à transformer
     * @return Retourne une liste de 8 boolean représentant le byte
     */
    private static boolean[] byteToBoolArr(byte b) {
        boolean boolArr[] = new boolean[8];
        for(int i=0;i<8;i++) boolArr[i] = (b & (byte)(128 / Math.pow(2, i))) != 0;
        return boolArr;
    }
    
    /**
     * Transforme une liste de 8 boolean en un byte
     * @param bs Correspond à la liste de 8 boolean
     * @return Retourne un byte représentant la liste de 8 boolean
     */
    private static byte boolArrToByte(boolean[] bs){
        int size = bs.length;
        byte b = 0;
        boolean signed = bs[0];
        for(int i=0;i<bs.length-1;i++){
            if(signed){
                b += (!bs[size-1-i]) ? Math.pow(2, i) : 0;
            }else{
                b += (bs[size-1-i]) ? Math.pow(2, i) : 0;
            }
        }
        return (byte) ((signed) ? (-1*b-1) : b);
    }
    
    
    
}