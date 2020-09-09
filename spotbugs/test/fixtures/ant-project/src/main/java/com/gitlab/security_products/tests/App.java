package com.gitlab.security_products.tests;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;

/**
 * Hello world!
 *
 */
public class App
{
    static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    static final String DB_URL = "jdbc:mysql://localhost/EMP";
    static final String USER = "username";
    static final String PASS = "pass";

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

    // Vulnerability - Dm: Hardcoded constant database password
    public void connectDB(){
        Connection conn = null;
        Statement stmt = null;
        try{
            Class.forName("com.mysql.jdbc.Driver");
            System.out.println("Connecting to database...");
            conn = DriverManager.getConnection(DB_URL,USER,PASS);
            stmt = conn.createStatement();
            String sql;
            String name = "john";
            sql = "SELECT id, first, last, age FROM Employees where first = "+ name;
            ResultSet rs = stmt.executeQuery(sql);
        }catch(SQLException se){
            se.printStackTrace();
        }catch(Exception e){
            e.printStackTrace();
        }finally{
        }
    }

}
