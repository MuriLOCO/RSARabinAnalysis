package com.concordia.RSARabinAnalysis;

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

		rsaEncryptDecrypt(512);
		rsaEncryptDecrypt(1024);
		rsaEncryptDecrypt(2048);
		rsaEncryptDecrypt(4096);
	}
	
	private static void rsaEncryptDecrypt(int keySize) throws Exception {
		System.out.println("------" + keySize + " key size! ------");
		
		KeyPair keyPair = Utils.buildKeyPair(keySize);    
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        
        System.out.println("Public key: " + publicKey);
        System.out.println("Private key p: " + privateKey.getPrimeP());
        System.out.println("Private key q: " + privateKey.getPrimeQ());
        System.out.println("Private key e: " + privateKey.getPrivateExponent());
    
        final String text = IOUtils.toString(Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("text.txt"), "UTF-8");        
  
        System.out.println("Text has: " + text.getBytes("UTF-8").length + " bytes.");
        
        long totalEncryption = Runtime.getRuntime().totalMemory()/1000000;        
        //System.out.println("Total memory before Encryption: " + totalEncryption);   
        
        long startTimeEncrypt = System.nanoTime();
        byte [] encrypted = Utils.encrypt(privateKey, text);
        long endTimeEncrypt = System.nanoTime();
        long durationEncrypt = (endTimeEncrypt - startTimeEncrypt)/1000000;
        System.out.println("Encryption time in ms: " + durationEncrypt);
        System.out.println(new String(encrypted));  
        long usedEncryption  = Runtime.getRuntime().totalMemory()/1000000 - Runtime.getRuntime().freeMemory()/1000000;
        //System.out.println("Total memory after Encryption: " + usedEncryption);
        long totalConsumedEncryption = totalEncryption - usedEncryption;
       // System.out.println("Was consumed for Encryption: " + totalConsumedEncryption);
        
        
        
        long totalDecryption = Runtime.getRuntime().totalMemory()/1000000;        
        //System.out.println("Total memory before Decryption: " + totalDecryption);
        long startTimeDecrypt = System.nanoTime();
        byte[] secret = Utils.decrypt(publicKey, encrypted);
        long endTimeDecrypt = System.nanoTime();
        long durationDecrypt= (endTimeDecrypt - startTimeDecrypt)/1000000;
        long usedDecryption  = Runtime.getRuntime().totalMemory()/1000000 - Runtime.getRuntime().freeMemory()/1000000;
       // System.out.println("Total memory after Decryption: " + durationDecrypt);
        long totalConsumedDecryption = totalDecryption - usedDecryption;
       // System.out.println("Was consumed for Decryption: " + totalConsumedDecryption);
        System.out.println(new String(secret));  
	}
}
