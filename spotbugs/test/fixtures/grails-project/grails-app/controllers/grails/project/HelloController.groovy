package grails.project

import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import groovy.transform.CompileStatic

@CompileStatic
class HelloController {

    def index() { }

    // This method triggers a findbugs issue with "BAD_PRACTICE" category
    Boolean booleanMethod() {
        null
    }

    // This method triggers a findbugs issue with "SECURITY" category
    def insecureCypher() {
        try {
            Cipher c = Cipher.getInstance "AES/ECB/NoPadding"
            Key k = KeyGenerator.getInstance("AES").generateKey()
            SecureRandom r = new SecureRandom()
            c.init(Cipher.ENCRYPT_MODE, k, r)
            byte[] plainText= "plainText".getBytes()
            byte[] cipherText = c.doFinal(plainText)
        } catch (Exception e) {/* LOG YOUR EXCEPTION */}
    }

    // This method triggers a findbugs issue with "SECURITY" category (needs findsecbugs plugin)
    def generateSecretToken1() {
        Random r = new Random()
        Long.toHexString r.nextLong()
    }

    // This method triggers a findbugs issue with "SECURITY" category (needs findsecbugs plugin)
    def generateSecretToken2() {
        Random r = new Random()
        Long.toHexString r.nextLong()
    }
}


