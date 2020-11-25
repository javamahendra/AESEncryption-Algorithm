package com.app.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * It Handles AES (acronym of Advanced Encryption Standard) is a symmetric
 * encryption algorithm. AES was designed to be efficient in both hardware and
 * software, and supports a block length of 128 bits and key lengths of 128,
 * 192, and 256 bits.
 * 
 */

public class AESEncryption {

	// Default Constructor.
	public AESEncryption() {

	}
	
	public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static final String AES_ALGORITHM = "AES";
	public static final int ENC_BITS = 256;
	public static final String CHARACTER_ENCODING = "UTF-8";
	public static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
	

	/**
	 * This method is used encode the data
	 *
	 * @param bytes
	 *            : to encode
	 * @return : String data as a encoded
	 */
	public String encodeBase64String(byte[] bytes) {
		return new String(java.util.Base64.getEncoder().encode(bytes));
	}

	/**
	 * /** This method is used decode the string data
	 *
	 * @param stringData
	 *            : to decode
	 * @return : decodeBase64StringTOByte
	 * @throws UnsupportedEncodingException
	 */
	public byte[] decodeBase64StringTOByte(String stringData) throws UnsupportedEncodingException {
		return java.util.Base64.getDecoder().decode(stringData.getBytes(CHARACTER_ENCODING));
	}

	/**
	 * This method is used to generate secure key.
	 *
	 * @return : Generated Secure Key as a String
	 * @throws NoSuchAlgorithmException
	 */
	public String generateSecureKey(String algorithm) throws NoSuchAlgorithmException {
		if(algorithm != null) {
			algorithm = AES_ALGORITHM;
		}
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(ENC_BITS);
		SecretKey secretKey = keyGenerator.generateKey();
		return encodeBase64String(secretKey.getEncoded());
	}

	/**
	 * This method is used to decrypt base64 encoded string using an AES 256 bit
	 * key.
	 *
	 * @param plainText
	 *            : plain text to encrpyt
	 * @param secret
	 *            : key to encrypt
	 * @return : Encrypted String
	 * @throws Exception
	 */

	public String encryptEK(byte[] plainText, byte[] secret) throws Exception {
		String encryptEk;
		try {
			Cipher encryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, sk);
			encryptEk = Base64.encodeBase64String(encryptCipher.doFinal(plainText));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new Exception(e.getMessage());
		} catch (InvalidKeyException e) {
			throw new Exception(e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new Exception(e.getMessage());
		} catch (BadPaddingException e) {
			throw new Exception(e.getMessage());
		}
		// log.info(CLASSNAME + methodName + "End");
		return encryptEk;

	}

	/**
	 * This method is used to decrypt base64 encoded string using an AES 256 bit
	 * key.
	 *
	 * @param plainText
	 *            : plain text to decrypt
	 * @param secret
	 *            : key to decrypt
	 * @return : Decrypted String
	 * @throws Exception
	 * 
	 */
	public byte[] decrypt(String plainText, byte[] secret) throws Exception {
		return decrypt(Base64.decodeBase64(plainText), secret);
	}
	
	/**
	 * This method is used to decrypt base64 encoded string using an AES 256 bit
	 * key.
	 *
	 * @param plainText
	 *            : plain text to decrypt
	 * @param secret
	 *            : key to decrypt
	 * @return : Decrypted String
	 * @throws Exception
	 * 
	 */
	public byte[] decrypt(byte[] content, byte[] secret) throws Exception {
		byte[] cipherText;
		try {
			Cipher decryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
			decryptCipher.init(Cipher.DECRYPT_MODE, sk);
			cipherText = decryptCipher.doFinal(content);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new Exception(e.getMessage());
		} catch (InvalidKeyException e) {
			throw new Exception(e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new Exception(e.getMessage());
		} catch (BadPaddingException e) {
			throw new Exception(e.getMessage());
		}
		return cipherText;
	}

}
