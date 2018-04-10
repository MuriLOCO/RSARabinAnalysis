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

    rsaRabinEncryptDecrypt(512);
    rsaRabinEncryptDecrypt(1024);
    rsaRabinEncryptDecrypt(2048);
    rsaRabinEncryptDecrypt(4096);
    rsaRabinEncryptDecrypt(8192);
  }

  /**
   * Performs the encryption and decryption analysis of RSA and Rabin
   * @param keySize - Key Size
   * @throws Exception
   */
  private static void rsaRabinEncryptDecrypt(int keySize) throws Exception {
    System.out.println("------" + keySize + " key size! ------");

    //Creation of Key
    long startTimeKeyCreation = System.nanoTime();
    KeyPair keyPair = Utils.buildRSARabinKeyPair(keySize);
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
    long endTimeKeyCreation = System.nanoTime();
    long durationKeyCreation = (endTimeKeyCreation - startTimeKeyCreation);
    System.out.println("Key creation time: " + durationKeyCreation);

    final String text = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("text.txt"), "UTF-8");

    //Encrypting RSA
    long startTimeEncryptRSA = System.nanoTime();
    BigInteger encryptedRSA = Utils.encryptRSA(publicKey, text);
    long endTimeEncryptRSA = System.nanoTime();
    long durationEncryptRSA = (endTimeEncryptRSA - startTimeEncryptRSA);
    System.out.println("Encryption time RSA in ms: " + durationEncryptRSA);

    //Encrypting Rabin
    long startTimeEncryptRabin = System.nanoTime();
    BigInteger encryptedRabin = Utils.encryptRabin(publicKey, text);
    long endTimeEncryptRabin = System.nanoTime();
    long durationEncryptRabin = (endTimeEncryptRabin - startTimeEncryptRabin);
    System.out.println("Encryption time Rabin in ms: " + durationEncryptRabin);

    //Decrypting RSA
    long startTimeDecryptRSA = System.nanoTime();
    Utils.decryptRSA(privateKey, encryptedRSA);
    long endTimeDecryptRSA = System.nanoTime();
    long durationDecryptRSA = (endTimeDecryptRSA - startTimeDecryptRSA);
    System.out.println("Deryption time RSA in ms: " + durationDecryptRSA);

    //Decrypting Rabin
    long startTimeDecryptRabin = System.nanoTime();
    Utils.decryptRabin(privateKey, encryptedRabin);
    long endTimeDecryptRabin = System.nanoTime();
    long durationDecryptRabint = (endTimeDecryptRabin - startTimeDecryptRabin);
    System.out.println("Deryption time Rabin in ms: " + durationDecryptRabint);

  }

}
