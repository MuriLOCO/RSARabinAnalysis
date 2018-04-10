package com.concordia.RSARabinAnalysis.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

  public static List<BigInteger> decryptRabin(RSAPrivateCrtKey privateKey, BigInteger message) {
    BigInteger constraintPPos = message.modPow((privateKey.getPrimeP().add(BigInteger.ONE)).divide(FOUR),
          privateKey.getPrimeP());
    BigInteger constraintPNeg = constraintPPos.negate();
    BigInteger constraintQPos = message.modPow((privateKey.getPrimeQ().add(BigInteger.ONE)).divide(FOUR),
          privateKey.getPrimeQ());
    BigInteger constraintQNeg = constraintQPos.negate();

    List<BigInteger> decryptedMessages = new ArrayList<>();
    decryptedMessages.add(calculateCRT(Arrays.asList(constraintPPos, constraintQPos),
          Arrays.asList(privateKey.getPrimeP(), privateKey.getPrimeQ())));
    decryptedMessages.add(calculateCRT(Arrays.asList(constraintPNeg, constraintQPos),
          Arrays.asList(privateKey.getPrimeP(), privateKey.getPrimeQ())));
    decryptedMessages.add(calculateCRT(Arrays.asList(constraintPPos, constraintQNeg),
          Arrays.asList(privateKey.getPrimeP(), privateKey.getPrimeQ())));
    decryptedMessages.add(calculateCRT(Arrays.asList(constraintPNeg, constraintQNeg),
          Arrays.asList(privateKey.getPrimeP(), privateKey.getPrimeQ())));

    return decryptedMessages;
  }

  /* *//**
       * Decrypt a value with the private key (assumes blum key for fast decryption)
       * @param message encrypted message
       * @param p private key, p
       * @param q private key, q
       * @return array of the 4 decryption possibilities
       */

  /*
  public static BigInteger[] decryptRabin(RSAPrivateCrtKey privateKey, BigInteger message) {
  BigInteger p = privateKey.getPrimeExponentP();
  BigInteger q = privateKey.getPrimeExponentQ();
  BigInteger N = privateKey.getModulus();
  BigInteger m_p1 = message.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
  BigInteger m_p2 = p.subtract(m_p1);
  BigInteger m_q1 = message.modPow(q.add(BigInteger.ONE).divide(FOUR), q);
  BigInteger m_q2 = q.subtract(m_q1);
  
  BigInteger[] ext = getGcd(p, q);
  BigInteger y_p = ext[1];
  BigInteger y_q = ext[2];
  
  //y_p*p*m_q + y_q*q*m_p (mod n)
  BigInteger d1 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p1)).mod(N);
  BigInteger d2 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p1)).mod(N);
  BigInteger d3 = y_p.multiply(p).multiply(m_q1).add(y_q.multiply(q).multiply(m_p2)).mod(N);
  BigInteger d4 = y_p.multiply(p).multiply(m_q2).add(y_q.multiply(q).multiply(m_p2)).mod(N);
  
  return new BigInteger[] { d1, d2, d3, d4 };
  }
  
  *//**
          * Gets the GCD of an array of numbers
          * @param a - Nubmer 1
          * @param b - Number 2
          * @return - GCD of 1 with 2
          *//*
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
                  }*/

  private static List<BigInteger> euclidean(BigInteger a, BigInteger b) {
    if (b.compareTo(a) == 1) {
      //reverse the order of inputs, run through this method, then reverse outputs
      List<BigInteger> coeffs = new ArrayList<>();
      List<BigInteger> output = new ArrayList<>();
      coeffs = euclidean(b, a);
      output.add(coeffs.get(1));
      output.add(coeffs.get(0));
      return output;
    }
    BigInteger q = a.divide(b);
    BigInteger r = a.subtract(q.multiply(b));

    if (r.equals(BigInteger.ZERO)) {
      List<BigInteger> output = new ArrayList<>();
      output.add(BigInteger.ZERO);
      output.add(BigInteger.ONE);
      return output;
    }
    List<BigInteger> next = new ArrayList<>();
    next = euclidean(b, r);
    List<BigInteger> output = new ArrayList<>();
    output.add(next.get(1));
    output.add(next.get(0).subtract(q.multiply(next.get(1))));
    return output;
  }

  private static BigInteger leastPosEquiv(BigInteger a, BigInteger m) {

    if (m.compareTo(BigInteger.ZERO) == -1)
      return leastPosEquiv(a, BigInteger.ONE.negate().multiply(m));

    if ((a.compareTo(BigInteger.ZERO) == 1 || a.compareTo(BigInteger.ZERO) == 0) && a.compareTo(m) == -1)
      return a;

    if (a.compareTo(BigInteger.ZERO) == -1)
      return m.add(BigInteger.ONE.negate().multiply(leastPosEquiv(BigInteger.ONE.negate().multiply(a), m)));

    BigInteger q = a.divide(m);

    return a.subtract(q.multiply(m));
  }

  private static BigInteger calculateCRT(List<BigInteger> constraints, List<BigInteger> mods) {
    BigInteger M = BigInteger.ONE;
    for (int i = 0; i < mods.size(); i++)
      M = mods.get(i).multiply(M);

    List<BigInteger> multInv = new ArrayList<>();
    for (int i = 0; i < constraints.size(); i++)
      multInv.add(euclidean(M.divide(mods.get(i)), mods.get(i)).get(0));

    BigInteger x = BigInteger.ZERO;

    for (int i = 0; i < mods.size(); i++)
      x = x.add(M.divide(mods.get(i)).multiply(constraints.get(i).multiply(multInv.get(i))));

    return leastPosEquiv(x, M);
  }

}
