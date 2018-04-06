package com.concordia.RSARabinAnalysis.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class Utils {

  private static final BigInteger TWO = new BigInteger("2");
  private static final BigInteger THREE = new BigInteger("3");
  private static final BigInteger FOUR = new BigInteger("4");

  public static KeyPair buildRSARabinKeyPair(int keySize) throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.genKeyPair();

    RSAPrivateCrtKey rsaKeyPair = (RSAPrivateCrtKey) keyPair.getPrivate();
    if (!rsaKeyPair.getPrimeQ().mod(FOUR).equals(THREE) || !rsaKeyPair.getPrimeP().mod(FOUR).equals(THREE))
      buildRSARabinKeyPair(keySize);

    return keyPairGenerator.genKeyPair();
  }

  public static BigInteger encryptRSA(RSAPublicKey publicKey, String message) throws Exception {
    return new BigInteger(message.getBytes()).modPow(publicKey.getPublicExponent(), publicKey.getModulus());
  }

  public static BigInteger decryptRSA(RSAPrivateCrtKey privateKey, BigInteger encrypted) throws Exception {
    return encrypted.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
  }

  public static BigInteger encryptRabin(RSAPublicKey publicKey, String message) throws Exception {
    BigInteger bigIntegerMessage = new BigInteger(message.getBytes());
    BigInteger encryptedMessage = bigIntegerMessage.modPow(TWO, publicKey.getModulus());
    return encryptedMessage;
  }


}
