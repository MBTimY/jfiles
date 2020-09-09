package com.gitlab.security_products.tests;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }

    // This method triggers a findbugs issue with "BAD_PRACTICE" category
    public Boolean booleanMethod() {
        return null;
    }

    // This method triggers a findbugs issue with "SECURITY" category
    public void insecureCypher() {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            Key k = KeyGenerator.getInstance("AES").generateKey();
            SecureRandom r = new SecureRandom();
            c.init(Cipher.ENCRYPT_MODE, k, r);
            byte[] plainText= "plainText".getBytes();
            byte[] cipherText = c.doFinal(plainText);
        } catch (Exception e) {/* LOG YOUR EXCEPTION */}

    }

    // This method triggers a findbugs issue with "SECURITY" category (needs findsecbugs plugin)
    String generateSecretToken1() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }

    // This method triggers a findbugs issue with "SECURITY" category (needs findsecbugs plugin)
    String generateSecretToken2() {
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }
}
