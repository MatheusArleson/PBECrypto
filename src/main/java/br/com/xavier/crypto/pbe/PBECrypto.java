package br.com.xavier.crypto.pbe;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import br.com.xavier.crypto.KeySize;

public class PBECrypto {
	
	//XXX PROPERTIES
	private final Charset charset;
	private final Integer numberOfIterationsForKeyGeneration;
	private final KeySize keySize;
	private final Cipher cipher;
	private final SecretKeyFactory keyFactory;
	private final SecureRandom secureRandomSaltGenerator;

	//XXX CONSTRUCTOR
	public PBECrypto(int numberOfIterations, KeySize keySize, Charset charset) throws GeneralSecurityException {
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		secureRandomSaltGenerator = new SecureRandom();
		
		if(numberOfIterations < 1){
			this.numberOfIterationsForKeyGeneration = 65536;
		} else {
			this.numberOfIterationsForKeyGeneration = numberOfIterations;
		}
		
		if(keySize == null){
			this.keySize = KeySize.BITS_256;
		} else {
			this.keySize = keySize;
		}
		
		if(charset == null){
			this.charset = Charset.forName("UTF-8");
		} else {
			this.charset = charset;
		}
	}

	//XXX ENCRYPT METHODS
	public PBEStorage encrypt(char[] password) throws GeneralSecurityException {
		SecretKey key = deriveKey(password);

		cipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters params = cipher.getParameters();
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] ciphertext = cipher.doFinal(convertToByteArray(password));

		PBEStorage pbeStorage = new PBEStorage(iv, ciphertext, key);
		return pbeStorage;
	}
	
	private SecretKey deriveKey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] salt = generateSalt();
		
		PBEKeySpec spec = new PBEKeySpec(password, salt, numberOfIterationsForKeyGeneration.intValue(), keySize.getKeySize());
		SecretKey tmp = keyFactory.generateSecret(spec);
		
		spec.clearPassword();
		
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
		return key;
	}

	private byte[] generateSalt() {
		byte[] saltBytes = new byte[20];
		secureRandomSaltGenerator.nextBytes(saltBytes);
		return saltBytes;
	}

	//XXX DECRYPT METHODS
	public char[] decrypt(PBEStorage pbeStorage) throws GeneralSecurityException {
		IvParameterSpec ivParameterSpec = new IvParameterSpec(pbeStorage.getInitializationVector());
		
		cipher.init(Cipher.DECRYPT_MODE, pbeStorage.getKey(), ivParameterSpec);
		byte[] decryptedContent = cipher.doFinal(pbeStorage.getCipherText());
		return convertToCharArray(decryptedContent);
	}

	// XXX UTIL METHODS
	private char[] convertToCharArray(byte[] byteArray) {
		ByteBuffer bb = ByteBuffer.wrap(byteArray);
		CharBuffer cb = charset.decode(bb);
		return cb.array();
	}

	private byte[] convertToByteArray(char[] charArray) {
		CharBuffer cb = CharBuffer.wrap(charArray);
		ByteBuffer bb = charset.encode(cb);
		return bb.array();
	}
}
