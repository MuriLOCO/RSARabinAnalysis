package com.concordia.RSARabinAnalysis;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.concordia.RSARabinAnalysis.utils.Utils;

@SpringBootApplication
public class RsaRabinAnalysisApplication {

  public static void main(String[] args) throws Exception {
    SpringApplication.run(RsaRabinAnalysisApplication.class, args);
    // rabinEncrptDecrypt(512);
    rsaEncryptDecrypt(512);
    rsaEncryptDecrypt(1024);
    rsaEncryptDecrypt(2048);
    rsaEncryptDecrypt(4096);
    rsaEncryptDecrypt(8192);
    rsaEncryptDecrypt(16384);
  }

  private static void rsaEncryptDecrypt(int keySize) throws Exception {
    System.out.println("------" + keySize + " key size! ------");

    //Creation of Key
    long startTimeKeyCreation = System.nanoTime();
    KeyPair keyPair = Utils.buildRSARabinKeyPair(keySize);
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    long endTimeKeyCreation = System.nanoTime();
    long durationKeyCreation = (endTimeKeyCreation - startTimeKeyCreation) / 1000000;
    System.out.println("Key creation time: " + durationKeyCreation);

    final String text = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("text.txt"), "UTF-8");

    //Encrypting RSA
    long startTimeEncryptRSA = System.nanoTime();
    BigInteger encryptedRSA = Utils.encryptRSA(publicKey, text);
    long endTimeEncryptRSA = System.nanoTime();
    long durationEncryptRSA = (endTimeEncryptRSA - startTimeEncryptRSA) / 1000000;
    System.out.println("Encryption time RSA in ms: " + durationEncryptRSA);

    //Encrypting Rabin
    long startTimeEncryptRabin = System.nanoTime();
    BigInteger encryptedRabin = Utils.encryptRabin(publicKey, text);
    long endTimeEncryptRabin = System.nanoTime();
    long durationEncryptRabin = (endTimeEncryptRabin - startTimeEncryptRabin) / 1000000;
    System.out.println("Encryption time Rabin in ms: " + durationEncryptRabin);

    
    //Decrypting RSA
    long startTimeDecryptRSA = System.nanoTime();
    Utils.decryptRSA(privateKey, encryptedRSA);
    long endTimeDecrypt = System.nanoTime();
    long durationDecrypt = (endTimeDecrypt - startTimeDecryptRSA) / 1000000;
    System.out.println("Deryption time RSA in ms: " + durationDecrypt);

  }

  private static void rabinEncrptDecrypt(int keySize) throws Exception {
    long startTimeKeyCreation = System.nanoTime();
    KeyPair keyPair = Utils.buildRabinKeyPair(keySize);

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    long endTimeKeyCreation = System.nanoTime();
    long durationKeyCreation = (endTimeKeyCreation - startTimeKeyCreation) / 1000000;
    System.out.println("Key creation time: " + durationKeyCreation);

    final String text = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("text.txt"), "UTF-8");

  }
}
