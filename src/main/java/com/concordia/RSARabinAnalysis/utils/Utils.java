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

  /**
   * Generates the key pair for RSA and Rabin
   * @param keySize - Key size
   * @return - Key Pair
   * @throws NoSuchAlgorithmException
   */
  public static KeyPair buildRSARabinKeyPair(int keySize) throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.genKeyPair();

    RSAPrivateCrtKey rsaKeyPair = (RSAPrivateCrtKey) keyPair.getPrivate();
    if (!rsaKeyPair.getPrimeQ().mod(FOUR).equals(THREE) || !rsaKeyPair.getPrimeP().mod(FOUR).equals(THREE))
      buildRSARabinKeyPair(keySize);

    return keyPairGenerator.genKeyPair();
  }

  /**
   * Encrypt the message using RSA algorithm
   * @param publicKey - Public Key
   * @param message - Message
   * @return - Cipher text
   * @throws Exception
   */
  public static BigInteger encryptRSA(RSAPublicKey publicKey, String message) throws Exception {
    return new BigInteger(message.getBytes()).modPow(publicKey.getPublicExponent(), publicKey.getModulus());
  }

  /**
   * Decrypts the cipher text using RSA algorithm
   * @param privateKey - Private Key
   * @param cipherMessage - Encrypted message 
   * @return - Decryped message
   * @throws Exception
   */
  public static BigInteger decryptRSA(RSAPrivateCrtKey privateKey, BigInteger cipherMessage) throws Exception {
    return cipherMessage.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
  }

  /**
   * Encrypts the message using RAbin algorithm
   * @param publicKey - Public Key
   * @param message - Message
   * @return - Cipher Message
   * @throws Exception
   */
  public static BigInteger encryptRabin(RSAPublicKey publicKey, String message) throws Exception {
    BigInteger bigIntegerMessage = new BigInteger(message.getBytes());
    BigInteger encryptedMessage = bigIntegerMessage.modPow(TWO, publicKey.getModulus());
    return encryptedMessage;
  }

  /**
   * Decrypt a value with the private key (assumes blum key for fast decryption)
   * @param cipherMessage encrypted message
   * @param privateKey - Private Key
   * @return array of the 4 decryption possibilities
   */
  public static BigInteger[] decryptRabin(RSAPrivateCrtKey privateKey, BigInteger cipherMessage) {
    BigInteger p = privateKey.getPrimeExponentP();
    BigInteger q = privateKey.getPrimeExponentQ();
    BigInteger N = privateKey.getModulus();
    BigInteger m_p1 = cipherMessage.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
    BigInteger m_p2 = p.subtract(m_p1);
    BigInteger m_q1 = cipherMessage.modPow(q.add(BigInteger.ONE).divide(FOUR), q);
    BigInteger m_q2 = q.subtract(m_q1);

    BigInteger[] ext = getGcd(p, q);
    BigInteger y_p = ext[1];
    BigInteger y_q = ext[2];

    BigInteger d1 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p1)).mod(N);
    BigInteger d2 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p1)).mod(N);
    BigInteger d3 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p2)).mod(N);
    BigInteger d4 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p2)).mod(N);

    return new BigInteger[] { d1, d2, d3, d4 };
  }

  /**
   * Gets the GCD of an array of numbers
   * @param a - Nubmer 1
   * @param b - Number 2
   * @return - GCD of 1 with 2
   */
  private static BigInteger[] getGcd(BigInteger a, BigInteger b) {
    BigInteger s = BigInteger.ZERO;
    BigInteger old_s = BigInteger.ONE;
    BigInteger t = BigInteger.ONE;
    BigInteger old_t = BigInteger.ZERO;
    BigInteger r = b;
    BigInteger old_r = a;
    while (!r.equals(BigInteger.ZERO)) {
      BigInteger q = old_r.divide(r);
      BigInteger tr = r;
      r = old_r.subtract(q.multiply(r));
      old_r = tr;

      BigInteger ts = s;
      s = old_s.subtract(q.multiply(s));
      old_s = ts;

      BigInteger tt = t;
      t = old_t.subtract(q.multiply(t));
      old_t = tt;
    }
    return new BigInteger[] { old_r, old_s, old_t };
  }
}
