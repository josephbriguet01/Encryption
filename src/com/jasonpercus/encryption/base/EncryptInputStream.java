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
 * Un objet EncryptInputStream obtient des octets d'entrée chiffrés en une autre base que 256
 * @see java.io.InputStream
 * @author JasonPercus
 * @version 1.0
 */
public abstract class EncryptInputStream extends java.io.InputStream implements Comparable<EncryptInputStream> {
    
    
    
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
     * Correspond à la base utilisée pour chiffrer
     */
    private final Base base;
    
    /**
     * Correspond à l'input d'entré
     */
    private final java.io.InputStream input;
    
    /**
     * Correspond à la séquence chiffrée. Tous les nombres de cette séquence doivent être renvoyé un par un
     */
    private byte[] temp;
    
    /**
     * Correspond à la position de lecture dans la séquence (voir {@link #temp})
     */
    private int position = 0;
    
    /**
     * Correspond au nombre d'octets qui composeront la chaîne chiffrée du stream
     */
    private long size;
    
    /**
     * Correspond au nombre d'octets déjà lu
     */
    private long read;
    
    /**
     * Correspond au nombre d'octets disponible;
     */
    private int inputAvailable = -1;
    
    
    
//CONSTRUCTORS
    /**
     * Crée un flux EncryptInputStream par défaut
     * @deprecated <div style="color: #D45B5B; font-style: italic">N'est pas utilisable.</div>
     */
    @Deprecated
    private EncryptInputStream() {
        throw new UnsupportedOperationException("Method not supported.");
    }
    
    /**
     * Crée un flux EncryptInputStream qui aura pour but de chiffrer un flux dans une autre base que 256
     * @param input Correspond au flux à chiffrer
     * @param base Correspond à la base qui servira de chiffrement (ex: s'il s'agit d'une base 64, alors le flux passera d'une base 256 à 64)
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    public EncryptInputStream(java.io.InputStream input, Base base) throws java.io.IOException {
        this.id     = cptID++;
        this.base   = base;
        this.input  = input;
        this.size = (input.available() * 8 / base.getNbBitsBase()) + (input.available() * 8 % base.getNbBitsBase() > 0 ? 1 : 0);
    }

    
    
//METHODES PUBLICS
    /**
     * Lit l'octet suivant de données dans le flux d'entrée. L'octet de valeur est renvoyé sous la forme d'un int chiffré grace à la base dans le constructeur. Si aucun octet n'est disponible car la fin du flux a été atteinte, la valeur -1 est renvoyée. Cette méthode se bloque jusqu'à ce que les données d'entrée soient disponibles, que la fin du flux soit détectée ou qu'une exception soit levée
     * @return Retourne l'octet suivant de données chiffré, ou -1 si la fin du flux est atteinte.
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    @Override
    public int read() throws java.io.IOException {
        if(inputAvailable == -1) inputAvailable = input.available();
        int rest = inputAvailable;
        if(temp == null){
            if(rest <= 0)
                return -1;
            else{
                position = 0;
                do{
                    temp = base.nextByteToEncrypt((byte) input.read(), rest <= 1);
                    inputAvailable--;
                    if(inputAvailable < 0) inputAvailable = 0;
                }while(rest>0 && temp.length == 0);
            }
        }
        byte data = temp[position++];
        if(position >= temp.length)
            temp = null;
        read++;
        return data & 0xff;
    }

    /**
     * Renvoie une estimation du nombre d'octets qui peuvent être lus (ou ignorés) à partir de ce flux d'entrée sans blocage par le prochain appel d'une méthode pour ce flux d'entrée. L'appel suivant peut être le même thread ou un autre thread. Une seule lecture ou un saut de ces nombreux octets ne bloquera pas
     * @return Retourne une estimation du nombre d'octets qui peuvent être lus (ou sautés) à partir de ce flux d'entrée sans blocage ou 0 lorsqu'il atteint la fin du flux d'entrée
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    @Override
    public int available() throws java.io.IOException {
        int value = (int) (this.size - this.read);
        if(value < 0) return 0;
        else return value;
    }
    
    /**
     * Ferme ce flux d'entrée et libère toutes les ressources système associées au flux
     * @throws java.io.IOException Si une erreur d'E/S se produit
     */
    @Override
    public void close() throws java.io.IOException {
        input.close();
        super.close();
    }

    /**
     * Teste si ce flux d'entrée prend en charge les méthodes mark et reset. La prise en charge ou non de mark et reset est une propriété invariante d'une instance de flux d'entrée particulière
     * @return Retourne false (car les méthodes {@link #mark(int)} et {@link #reset()} ne sont pas supportées
     */
    @Override
    public boolean markSupported() {
        return false;
    }

    /**
     * Marque la position actuelle dans ce flux d'entrée
     * @param readlimit Correspond à la limite maximale d'octets pouvant être lus avant que la position de la marque ne devienne invalide
     * @deprecated <div style="color: #D45B5B; font-style: italic">À ne pas utiliser. Dans le cas d'un flux autre qu'une base 256, l'utilisation d'un marque ne peut avoir de sens.</div>
     */
    @Override
    @Deprecated
    public synchronized void mark(int readlimit) {
        
    }

    /**
     * Repositionne ce flux à la position au moment où la mark méthode a été appelée pour la dernière fois sur ce flux d'entrée
     * @throws java.io.IOException Si ce flux n'a pas été marqué ou si la marque a été invalidée
     * @deprecated <div style="color: #D45B5B; font-style: italic">À ne pas utiliser. Dans le cas d'un flux autre qu'une base 256, l'utilisation d'un marque ne peut avoir de sens.</div>
     */
    @Override
    @Deprecated
    public synchronized void reset() throws java.io.IOException {
        throw new java.io.IOException("mark is not supported !");
    }

    /**
     * Saute et supprime les n octets de données de ce flux d'entrée
     * @param n Correspond au nombre d'octets à sauter
     * @return Retourne le nombre réel d'octets ignorés
     * @throws java.io.IOException Si le flux ne prend pas en charge la recherche ou si une autre erreur d'E/S se produit
     * @deprecated <div style="color: #D45B5B; font-style: italic">À ne pas utiliser. Dans le cas d'un flux autre qu'une base 256, la recherche ne peut avoir de sens puisque les bytes sont fusionnés entre eux.</div>
     */
    @Override
    @Deprecated
    public long skip(long n) throws java.io.IOException {
        throw new java.io.IOException("skip is not supported !");
    }

    /**
     * Renvoie le hashCode() du Stream
     * @return Retourne le hashCode() du Stream
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 43 * hash + this.id;
        return hash;
    }

    /**
     * Détermine si deux EncryptInputStream sont identiques ou pas
     * @param obj Correspond au second objet EncryptInputStream à comparer au courant
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
        final EncryptInputStream other = (EncryptInputStream) obj;
        return this.id == other.id;
    }

    /**
     * Renvoie un EncryptInputStream objet sous la forme d'une chaîne de caractères
     * @return Retourne un EncryptInputStream objet sous la forme d'une chaîne de caractères
     */
    @Override
    public String toString() {
        return getClass().getSimpleName() + "{encrypted using "+base.getClass().getSimpleName()+"}";
    }
    
    /**
     * Compare deux EncryptInputStream
     * @param o Correspond au second EncryptInputStream à comparer au courant
     * @return Retourne le résultat de la comparaison
     */
    @Override
    public int compareTo(EncryptInputStream o) {
        if(this.id < o.id)
            return -1;
        else if (this.id > o.id)
            return 1;
        else
            return 0;
    }
    
    
    
}