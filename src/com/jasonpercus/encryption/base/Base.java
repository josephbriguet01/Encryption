/*
 * Copyright (C) BRIGUET Systems, Inc - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * Written by Briguet, 06/2020
 */
package com.jasonpercus.encryption.base;



import com.jasonpercus.encryption.exception.BaseException;
import com.jasonpercus.encryption.Encryption;
import com.jasonpercus.encryption.Type;



/**
 * Cette classe à pour vocation d'encoder ou de décoder des nombres en différentes bases
 * @see EncryptInputStream
 * @see EncryptOutputStream
 * @see DecryptInputStream
 * @see DecryptOutputStream
 * @author JasonPercus
 * @version 1.0
 */
public class Base extends Encryption implements Comparable<Base> {
    
    
    
//ATTRIBUT STATIC
    /**
     * Correspond au compteur d'id créant ainsi l'unicité de l'objet
     */
    private static int cptID = 0;

    
    
//ATTRIBUTS
    /**
     * Correspond à la base d'un byte (en l'occurence c'est toujours 8 (pour 8 bits) ici)
     */
    private final int baseOrigin;
    
    /**
     * Correspond au nombre de bits sur lesquels chaque bytes sera codé (6 = base64, car il faut 6 bits pour coder un nombre compris entre [0; 64]; 7 = base128; 8 = base256 ...)
     */
    private final int baseTarget;
    
    /**
     * Correspond à l'id de l'objet Base
     */
    private final int id;
    
    /**
     * Ce tableau contient les tailles des blocs récupérés de {@link #split(int[], int[], int, int, int)}. Le bloc principal étant toujours en position [1]. Ainsi on peut calculer la taille du bloc précédant le bloc principal [0] et le bloc suivant le bloc principal [2]. Ce qui explique que le tableau fait forcément 3 de taille.
     */
    private final int[] realSizes = new int[3];
    
    /**
     * Ce tableau contient les résultats des blocs récupérés de {@link #split(int[], int[], int, int, int)}. Le bloc principal étant toujours en position [1]. Ainsi on peut connaître le résultat du bloc précédant le bloc principal [0] et le bloc suivant le bloc principal [2]. Ce qui explique que le tableau fait forcément 3 de taille.
     */
    private final int[] results = new int[3];
    
    /**
     * Correspond au nombre de bit à capturer au prochain passage
     */
    private int toCapture;
    
    /**
     * Correspond à la position de départ ou l'on récupère le bloc principal [1] voir {@link #results}
     */
    private int offset = 0;
    
    /**
     * Correspond au nombre restant calculé du précédant byte
     */
    private int restLastNumber = 0;
    
    /**
     * Correspond à la taille en bits du nombre restant calculé du précédant byte voir {@link #restLastNumber}
     */
    private int sizeRestLastNumber = 0;
    
    /**
     * Correspond à la prochaine position ou sera enregistré le résultat d'un byte converti
     */
    private int cptArray = 0;
    
    /**
     * Correspond au nombre de bits récupéré pour obtenir un byte déconverti (fonctionne uniquement avec {@link #decrypt(byte[])} et {@link #nextByteToDecrypt(byte)}
     */
    private int cpt = 0;
    
    /**
     * Correspond au tableau ou seront stockés tous les bytes dé/converti. A savoir que {@link #nextByteToEncrypt(byte, boolean)} et {@link #nextByteToDecrypt(byte)} n'utilise pas ce tableau. En effet, ces deux méthodes sont plus réservé à la dé/conversion d'un flux. Ces flus peuvent être de très grandes tailles, d'où le non intérêt de stocker les résultat dans ce tableau
     */
    private byte[] array;
    
    /**
     * Détermine si un ancien nombre est stocké en attente d'une fusion avec le nouveau nombre
     */
    private boolean lastNumber = false;
    
    /**
     * Détermine si le processus de la conversion est en cours
     */
    private boolean started;
    
    /**
     * Correspond au buffer ou sont stockés temporairement les valeurs construites avant leur renvoi
     */
    private java.nio.ByteBuffer buffer;
    
    
    
//CONSTRUCTORS
    /**
     * Correspond au constructeur par défaut
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée.</div>
     */
    private Base() {
        throw new UnsupportedOperationException("Method not supported.");
    }

    /**
     * Crée une base (les bases sont des puissances de 2 comprises entre [2; 256])
     * @param base Correspond à la base de sortie pour une conversion et à la base d'entrée pour une déconversion (ex: 32 = base32, 64 = base64...)
     */
    public Base(int base) {
        if((this.baseTarget = base(base)) > 0){
            this.baseOrigin = 8;
            this.toCapture = this.baseTarget;
            this.id = cptID++;
        }else{
            throw new BaseException("The base must be a power of 2 between [2;256] (Example: 64 for Base64...) !");
        }
    }
    
    
    
//METHODES PUBLICS
    /**
     * Renvoie le type {@link Type#NO_KEY}
     * @return Retourne le type {@link Type#NO_KEY}
     */
    @Override
    public Type getType() {
        return Type.NO_KEY;
    }
    
    /**
     * Encode un tableau de bytes (base 256 car un byte contient 256 valeur possibles) en base n (n étant la valeur fournit au constructeur)
     * @param datas Correspond au tableau de bytes à encoder
     * @return Retourne un tableau de bytes en base n correspondant au tableau de bytes en base 256 en paramètre
     */
    @Override
    public synchronized final byte[] encrypt(byte[] datas){
        this.array = new byte[(datas.length * baseOrigin / baseTarget) + (datas.length * baseOrigin % baseTarget > 0 ? 1 : 0)];
        this.toCapture = this.baseTarget;
        this.offset = 0;
        this.restLastNumber = 0;
        this.sizeRestLastNumber = 0;
        this.lastNumber = false;
        this.cptArray = 0;
        this.cpt = 0;
        this.started = false;
        for(int i=0;i<datas.length;i++){
            int entier = datas[i];
            if(toCapture <= 0 && lastNumber){
                toCapture = baseTarget;
                array[cptArray++] = (byte)restLastNumber;
                restLastNumber = 0;
                sizeRestLastNumber = 0;
                lastNumber = false;
            }
            calculateEnc(entier, 0);
        }
        if(lastNumber){
            array[cptArray++] = (byte)restLastNumber;
        }
        
        return array;
    }
    
    /**
     * Décode un tableau de bytes étant en base n (n étant la valeur fournit au constructeur) en base 256 (car un byte contient 256 valeur possibles)
     * @param datas Correspond au tableau de bytes à décoder
     * @return Retourne un tableau de bytes en base 256 correspondant au tableau de bytes en base n en paramètre (n étant la valeur fournit au constructeur)
     */
    @Override
    public synchronized final byte[] decrypt(byte[] datas){
        array = new byte[datas.length * baseTarget / baseOrigin];
        this.toCapture = this.baseTarget;
        this.offset = 0;
        this.restLastNumber = -1;
        this.sizeRestLastNumber = 0;
        this.lastNumber = false;
        this.cptArray = 0;
        this.cpt = 0;
        this.started = false;
        for(int i=0;i<datas.length;i++){
            int entier = datas[i];
            int salt = baseOrigin - baseTarget;
            if(restLastNumber == -1){
                split(realSizes, results, entier, salt, baseTarget);
                cpt += realSizes[1];
                sizeRestLastNumber = baseOrigin - cpt;
                if(sizeRestLastNumber > 0)
                    restLastNumber = results[1] << sizeRestLastNumber;
                else
                    array[cptArray++] = (byte)results[1];
            }else{
                int peutCapture = (baseOrigin - salt <= sizeRestLastNumber) ? baseOrigin - salt : sizeRestLastNumber;
                cpt += peutCapture;
                split(realSizes, results, entier, salt, peutCapture);
                int number = restLastNumber + ((results[1] >> realSizes[2]) << baseOrigin - cpt);
                if(baseOrigin - cpt == 0){
                    array[cptArray++] = (byte) number;
                    cpt = 0;
                }
                if(realSizes[2]>0){
                    restLastNumber = results[2] << (baseOrigin - realSizes[2]);
                    cpt += realSizes[2];
                    sizeRestLastNumber = baseOrigin - cpt;
                }else{
                    if(cpt>0){
                        restLastNumber = number;
                        sizeRestLastNumber = baseOrigin - cpt;
                    }else{
                        restLastNumber = -1;
                        sizeRestLastNumber = 0;
                    }
                }
            }
        }
        return array;
    }

    /**
     * Chiffre dans une base la chaîne de caractères
     * @param chain Correspond à la chaîne de caractères à chiffrer
     * @return Retourne une chaîne de caractères chiffrée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée.</div>
     */
    @Override
    public String encrypt(String chain) {
        throw new UnsupportedOperationException("Method not supported.");
    }

    /**
     * Déchiffre dans une base la chaîne de caractères
     * @param chain Correspond à la chaîne de caractères à déchiffrer
     * @return Retourne une chaîne de caractères déchiffrée
     * @deprecated <div style="color: #D45B5B; font-style: italic">Cette méthode ne peut être utilisée.</div>
     */
    @Override
    public String decrypt(String chain) {
        throw new UnsupportedOperationException("Method not supported.");
    }
    
    /**
     * Encode un byte (base 256 car un byte contient 256 valeur possibles) en base n (n étant la valeur fournit au constructeur). Remarque: cette méthode a réellement une utilité pour encoder un flux de bytes
     * @see #nextByteToDecrypt(byte)
     * @param data Correspond au byte à encoder
     * @param lastByte S'agit-il du dernier byte à encoder ?
     * @return Retourne un tableau de bytes encodés. Remarque: cette méthode peut renvoyer régulièrement des tableaux vides, car la méthode à besoin d'être appelée une à plusieurs fois pour qu'elle réussisse à encoder un et/ou plusieurs bytes
     */
    public synchronized final byte[] nextByteToEncrypt(byte data, boolean lastByte){
        if(!started){
            this.toCapture = this.baseTarget;
            this.offset = 0;
            this.restLastNumber = 0;
            this.sizeRestLastNumber = 0;
            this.lastNumber = false;
            this.cptArray = 0;
            this.cpt = 0;
            this.started = true;
        }
        int entier = data;
        if(buffer == null)
            buffer = java.nio.ByteBuffer.allocate(10);
        if (toCapture <= 0 && lastNumber) {
            toCapture = baseTarget;
            buffer.put((byte) restLastNumber);
            restLastNumber = 0;
            sizeRestLastNumber = 0;
            lastNumber = false;
        }
        calculateNextByteEnc(buffer, entier, 0);
        if(lastNumber && lastByte){
            buffer.put((byte) restLastNumber);
        }
        
        return convert(buffer);
    }
    
    /**
     * Décode un byte étant en base n (n étant la valeur fournit au constructeur) en base 256 (car un byte contient 256 valeur possibles). Remarque: cette méthode a réellement une utilité pour décoder un flux de bytes
     * @see #nextByteToEncrypt(byte, boolean)
     * @param data Correspond au byte à décoder
     * @return Retourne un tableau de bytes décodés. Remarque: cette méthode peut renvoyer régulièrement des tableaux vides, car la méthode à besoin d'être appelée une à plusieurs fois pour qu'elle réussisse à décoder un et/ou plusieurs bytes
     */
    public synchronized final byte[] nextByteToDecrypt(byte data){
        if(!started){
            this.toCapture = this.baseTarget;
            this.offset = 0;
            this.restLastNumber = -1;
            this.sizeRestLastNumber = 0;
            this.lastNumber = false;
            this.cptArray = 0;
            this.cpt = 0;
            this.started = true;
        }
        int entier = data;
        if(buffer == null)
            buffer = java.nio.ByteBuffer.allocate(10);
        int salt = baseOrigin - baseTarget;
        if (restLastNumber == -1) {
            split(realSizes, results, entier, salt, baseTarget);
            cpt += realSizes[1];
            sizeRestLastNumber = baseOrigin - cpt;
            if (sizeRestLastNumber > 0) {
                restLastNumber = results[1] << sizeRestLastNumber;
            } else {
                buffer.put((byte) results[1]);
            }
        } else {
            int peutCapture = (baseOrigin - salt <= sizeRestLastNumber) ? baseOrigin - salt : sizeRestLastNumber;
            cpt += peutCapture;
            split(realSizes, results, entier, salt, peutCapture);
            int number = restLastNumber + ((results[1] >> realSizes[2]) << baseOrigin - cpt);
            if (baseOrigin - cpt == 0) {
                buffer.put((byte) number);
                cpt = 0;
            }
            if (realSizes[2] > 0) {
                restLastNumber = results[2] << (baseOrigin - realSizes[2]);
                cpt += realSizes[2];
                sizeRestLastNumber = baseOrigin - cpt;
            } else if (cpt > 0) {
                restLastNumber = number;
                sizeRestLastNumber = baseOrigin - cpt;
            } else {
                restLastNumber = -1;
                sizeRestLastNumber = 0;
            }
        }
        return convert(buffer);
    }
    
    /**
     * Reinitialise le système d'encodage/décodage d'une base à l'autre. Ainsi une nouvelle conversion peut être réalisée
     * @see #nextByteToEncrypt(byte, boolean)
     * @see #nextByteToDecrypt(byte)
     */
    public synchronized final void resetNextByte(){
        this.started = false;
    }
    
    /**
     * Renvoie le nombre de bits sur lesquels chaque bytes sera codé (6 = base64, car il faut 6 bits pour coder un nombre compris entre [0; 64]; 7 = base128; 8 = base256 ...)
     * @return Retourne le nombre de bits sur lesquels chaque bytes sera codé
     */
    public final int getNbBitsBase(){
        return this.baseTarget;
    }

    /**
     * Renvoie le hashCode de l'objet Base
     * @return Retourne le hashCode de l'objet Base
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + this.id;
        return hash;
    }

    /**
     * Détermine si deux objets Base sont identiques
     * @param obj Correspond au second objet à comparer au courant
     * @return Retourne true s'ils sont identiques
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
        final Base other = (Base) obj;
        return this.id == other.id;
    }

    /**
     * Renvoie un objet Base sous la forme d'une chaîne de caractères
     * @return Retourne un objet Base sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        return "Base{ On " +this.baseTarget+ " bit(s) }";
    }

    /**
     * Compare deux objet bases entre eux
     * @param o Correspond au second objet base à comparer au courant
     * @return Retourne le résultat de la comparaison
     */
    @Override
    public int compareTo(Base o) {
        if(this.id < o.id)
            return -1;
        else if (this.id > o.id)
            return 1;
        else
            return 0;
    }
    
    
    
//METHODES PRIVATES
    /**
     * Encode un entier
     * @param entier Correspond à l'entier à encoder
     * @param dec Correspond au décallage à effectuer sur le résulat
     */
    private void calculateEnc(int entier, int dec){
        split(realSizes, results, entier, offset, toCapture);
        int left = baseTarget - realSizes[2];
        int right = baseOrigin - toCapture;
        if (lastNumber) {
            array[cptArray++] = (byte)(restLastNumber + (results[1] >> right));
        } else {
            array[cptArray++] = (byte)(results[1] >> right);
        }
        
        if((baseTarget * 2 < baseOrigin && realSizes[2] > baseTarget && dec + baseTarget * 2 < baseOrigin) || (baseTarget * 2 >= baseOrigin && realSizes[2] > baseTarget)){
            toCapture = baseTarget;
            restLastNumber = 0;
            sizeRestLastNumber = 0;
            lastNumber = false;
            calculateEnc((results[2] >> dec) << baseOrigin - realSizes[2] + dec, baseOrigin - realSizes[2] + dec);
            return;
        }
        
        restLastNumber = (results[2] >> dec) << left + dec;
        sizeRestLastNumber = realSizes[2] - dec;
        lastNumber = realSizes[2] - dec > 0;
        toCapture = baseTarget - sizeRestLastNumber;
    }
    
    /**
     * Encode un entier
     * @param buffer Correspond au buffer où seront stockés les résultats de (seulement) ce nombre encodé
     * @param entier Correspond au nombre à encoder
     * @param dec Correspond au décallage à effectuer sur le résulat
     */
    private void calculateNextByteEnc(java.nio.ByteBuffer buffer, int entier, int dec){
        split(realSizes, results, entier, offset, toCapture);
        int left = baseTarget - realSizes[2];
        int right = baseOrigin - toCapture;
        if (lastNumber) {
            buffer.put((byte)(restLastNumber + (results[1] >> right)));
        } else {
            buffer.put((byte)(results[1] >> right));
        }
        
        if((baseTarget * 2 < baseOrigin && realSizes[2] > baseTarget && dec + baseTarget * 2 < baseOrigin) || (baseTarget * 2 >= baseOrigin && realSizes[2] > baseTarget)){
            toCapture = baseTarget;
            restLastNumber = 0;
            sizeRestLastNumber = 0;
            lastNumber = false;
            calculateNextByteEnc(buffer, (results[2] >> dec) << baseOrigin - realSizes[2] + dec, baseOrigin - realSizes[2] + dec);
            return;
        }
        
        restLastNumber = (results[2] >> dec) << left + dec;
        sizeRestLastNumber = realSizes[2] - dec;
        lastNumber = realSizes[2] - dec > 0;
        toCapture = baseTarget - sizeRestLastNumber;
    }
    
    /**
     * Découpe un entier en 3 parties. La seconde partie (la principale) commence à la position offset et fait length de taille. Ainsi on peut déterminer la partie 1 et 3
     * @param realSizes Correspond au tableau de chaque taille des parties. Voir {@link #realSizes}
     * @param results Correspond au tableau de chaque résultat des parties. Voir {@link #results}
     * @param number Correspond au nombre à découper
     * @param offset Correspond à la position de départ de la seconde partie
     * @param length Correspond à la taille de la seconde partie
     */
    private void split(int[] realSizes, int[] results, int number, int offset, int length){
        results[0] = subInt(number, 0, offset);
        results[1] = subInt(number, offset, length);
        results[2] = subInt(number, offset + length, baseOrigin - (offset + length));
        
        realSizes[0] = offset;
        realSizes[1] = length;
        realSizes[2] = baseOrigin - (offset + length);
    }
    
    /**
     * Récupère un sous entier d'un entier (ex: 85 = 01010101 en binaire. Si offset = 2 et length = 4, alors je récupère 00010100 en binaire = 20)
     * @param value Correspond à l'entier de base
     * @param offset Correspond à la position (en bits) du sous entier à récupérer
     * @param length Correspond à la taille (en bits) du sous entier à récupérer
     * @return Retourne le sous entier
     */
    private int subInt(int value, int offset, int length){
        return value & mask(offset, length);
    }
    
    /**
     * Crée le masque d'un byte (imaginons que le veut récupérer 20 (00010100) d'un entier 85 (01010101). Pour pouvoir récupérer 20, il va falloir appliquer un masque à 85 ce masque doit être 60 (00111100). 60 (en base2) & 85 (en base2) = 20. Pour créer le nombre 60, on a besoin d'un offset qui définit la position du premier 1 de (00111100) et d'une taille qui définit le nombre de 1. Donc dans notre exemple, offset = 2 et length = 4)
     * @param offset Correspond à la position du premier 1 du masque binaire
     * @param length Correspond au nombre de 1 du masque binaire
     * @return Retourne le masque d'un byte
     */
    private int mask(int offset, int length){
        int[] base = {128, 64, 32, 16, 8, 4, 2, 1};
        int mask = 0;
        for(int i=0;i<length;i++){
            mask += base[offset + i];
        }
        return mask;
    }
    
    /**
     * Détermine le nombre de bits utilisés pour une base (ex pour une base64: les 64 possibilités de bytes s'écrivent sur 6 bits, base32 = 5 bits...)
     * @param base Correspond à la base (2, 4, 8, 16, 32, 64, 128, 256)
     * @return Retourne le nombre de bits utilisés pour la base
     */
    private int base(int base){
        int[] types = {2, 4, 8, 16, 32, 64, 128, 256};
        for(int i=1;i<=types.length;i++){
            if(types[i-1] == base)
                return i;
        }
        return -1;
    }
    
    /**
     * Converti un buffer en un tableau de bytes (si le buffer est vide, alors le tableau est vide)
     * @param buffer Correspond au buffer à convertir
     * @return Retourne un tableau de byte
     */
    private byte[] convert(java.nio.ByteBuffer buffer){
        int count = buffer.position();
        if(count == 0){
            buffer.position(0);
            return new byte[0];
        }else{
            byte[] datas = new byte[count];
            for(int i=0;i<count;i++){
                datas[i] = buffer.get(i);
            }
            buffer.position(0);
            return datas;
        }
    }
    
    
    
}