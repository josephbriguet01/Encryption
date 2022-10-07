/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.base64;



import com.jasonpercus.encryption.base.Base;



/**
 * Cette classe à pour vocation d'encoder ou de décoder des nombres en base 64
 * @see Base
 * @see Type
 * @see EncryptInputStream
 * @see EncryptOutputStream
 * @see DecryptInputStream
 * @see DecryptOutputStream
 * @author JasonPercus
 * @version 1.0
 */
public final class Base64 extends Base {

    
    
//CONSTANTES
    /**
     * Correspond à la suite des caractères utilisables en Base64 [type 0]
     */
    private final static byte[] BASE                            = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
    
    /**
     * Correspond à la suite des caractères utilisables en Base64 avec le retour à la ligne [type 1]
     */
    private final static byte[] BASE_WITH_LINE_BREAK            = {10, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
    
    /**
     * Correspond à la suite des caractères utilisables en Base64 avec l'espace [type 2]
     */
    private final static byte[] BASE_WITH_SPACE                 = {65, 32, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
    
    /**
     * Correspond à la suite des caractères utilisables en Base64 avec le retour à la ligne et l'espace [type 3]
     */
    private final static byte[] BASE_WITH_LINE_BREAK_AND_SPACE  = {10, 32, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
    
    
    
//ATTRIBUT
    /**
     * Correspond au type de suite de caractères utilisables pour le dé/chiffrement
     * @see #BASE
     * @see #BASE_WITH_LINE_BREAK
     * @see #BASE_WITH_SPACE
     * @see #BASE_WITH_LINE_BREAK_AND_SPACE
     */
    private final Type type;
    
    
    
//CONSTRUCTORS
    /**
     * Crée un objet Base64 qui aura pour mission de dé/chiffrer des tableaux, des chaînes de caractères, des flux en base 64. Remarque: les chaînes de caractères ne contiendront ni de retour à la ligne, ni d'espace
     */
    public Base64() {
        this(Type.BASE);
    }

    /**
     * Crée un objet Base64 qui aura pour mission de dé/chiffrer des tableaux, des chaînes de caractères, des flux en base 64
     * @param type Correspond aux types de chaînes de caractères utilisées (avec retour à la ligne, avec espace, avec retour à la ligne et espace, ou sans retour à la ligne ni espace)
     */
    public Base64(Type type) {
        super(64);
        this.type = type;
    }

    
    
//METHODES PUBLICS
    /**
     * Chiffre un tableau de byte en une chaîne de caractères (base 64)
     * @param datas Correspond au tableau de bytes à chiffrer
     * @return Retourne une chaîne de caractères chiffrée en base 64
     */
    public String toString(byte[] datas){
        String chain = "";
        byte[] encryptedBytes = encrypt(datas);
        for(int i=0;i<encryptedBytes.length;i++){
            chain += byte64ToChar64(encryptedBytes[i]);
        }
        return chain;
    }
    
    /**
     * Déchiffre une chaîne de caractères (base 64) en un tableau de bytes
     * @param chain Correspond à la chaîne de caractères (base 64) à déchiffrer
     * @return Retourne un tableau de bytes
     */
    public byte[] toBytes(String chain){
        byte[] decryptedBytes = new byte[chain.length()];
        for(int i=0;i<decryptedBytes.length;i++){
            decryptedBytes[i] = char64ToByte64(chain.charAt(i));
        }
        return decrypt(decryptedBytes);
    }
    
    /**
     * Chiffre l'input et renvoie le résultat chiffré en une chaîne de caaractères (base 64)
     * @param input Correspond à l'input qui va être chiffré
     * @return Retourne une chaîne de caractère (base 64)
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public String inputToString(java.io.InputStream input) throws java.io.IOException {
        StringBuilder str = new StringBuilder();
        int value;
        try (EncryptInputStream eis = new EncryptInputStream(input)) {
            while((value = eis.read()) > -1){
                str.append(byte64ToChar64((byte)value));
            }
        }
        return str.toString();
    }
    
    /**
     * Déchiffre une chaîne de caractère (base 64) et écrit le résultat déchiffré dans l'output
     * @param chain Correspond à la chaîne (base 64) à déchiffrer
     * @param output Correspond à l'output où sera écrit le résultat déchiffré
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public void stringToOutput(String chain, java.io.OutputStream output) throws java.io.IOException {
        try (DecryptOutputStream dos = new DecryptOutputStream(output)) {
            for(int i=0;i<chain.length();i++){
                dos.write((int)(char64ToByte64(chain.charAt(i)) & 0xff));
            }
        }
    }
    
    /**
     * Converti un byte (base 64) en char (base 64)
     * @param data Correspond au byte (base 64) à convertir
     * @return Retourne un char (base 64)
     */
    public char byte64ToChar64(byte data){
        switch (type) {
            
            case WITH_LINE_BREAK:
                return (char)BASE_WITH_LINE_BREAK[(int)data];
                
            case WITH_SPACE:
                return (char)BASE_WITH_SPACE[(int)data];
                
            case WITH_LINE_BREAK_AND_SPACE:
                return (char)BASE_WITH_LINE_BREAK_AND_SPACE[(int)data];
                
            default:
                return (char)BASE[(int)data];
                
        }
    }
    
    /**
     * Converti un char (base 64) en byte (base 64)
     * @param character Correspond au caractère (base 64) à convertir
     * @return Retourne un byte (base 64)
     */
    public byte char64ToByte64(char character){
        return getByte((int)character);
    }
    
    
    
//METHODE PRIVATE
    /**
     * Converti un caractère ascii (base64) en byte
     * @param ascii Correspond au caractère ascii (base64) à convertir
     * @return Retourne un byte
     */
    private static byte getByte(int ascii){
        if(ascii == 10){
            return 0;
        }else if(ascii == 32){
            return 1;
        }else if(65<=ascii && ascii<=90){
            return (byte) (ascii - 65);
        }else if(97<=ascii && ascii<=122){
            return (byte) (ascii - 97 + 26);
        }else if(48<=ascii && ascii<=57){
            return (byte) (ascii + 4);
        }else if(ascii == 43){
            return (byte) 62;
        }else{
            return (byte) 63;
        }
    }
    
    
    
//ENUM
    /**
     * Cette classe énumère les types de suites de caractères utilisables pour le dé/chiffrement. Classique, avec un retour à la ligne, avec l'espace et avec le retour à la ligne et l'espace
     * @see Base64
     * @author JasonPercus
     * @version 1.0
     */
    public static enum Type {
        
        
        
        /**
         * Lorsque l'on souhaite dé/chiffrer de manière classique (sur une ligne et sans espace)
         */
        BASE,
        
        /**
         * Lorsque l'on souhaite dé/chiffrer sur plusieurs lignes et sans espace
         */
        WITH_LINE_BREAK,
        
        /**
         * Lorsque l'on souhaite dé/chiffrer sur une seule ligne mais avec des espaces
         */
        WITH_SPACE,
        
        /**
         * Lorsque l'on souhaite dé/chiffrer sur plusieurs lignes et avec des espaces
         */
        WITH_LINE_BREAK_AND_SPACE
        
        
        
    }
    
    
    
}