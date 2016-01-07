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

/**
 * 
 * Class to peform Password Based Encryption (PBE)
 * 
 * @author Matheus Arleson Sales Xavier
 *
 */
public class PBECrypto {
	
	//XXX STATIC PROPERTIES
	//CRYTO PROPERTIES
	//TODO pass those as parameters?
	private static final String cipherTransformation = "AES/CBC/PKCS5Padding";
	private static final String keyFactoryAlgorithm = "PBKDF2WithHmacSHA256";
	private static final String formatKeyAlgorithm = "AES";
	
	//DEFAULT PROPERTIES
	private static final Integer defaultNumberOfIteractions = 65536;
	private static final KeySize defaultKeySize = KeySize.BITS_256;
	private static final Charset defaultCharset = Charset.forName("UTF-8");
	
	//XXX INSTANCE PROPERTIES
	private final Charset charset;
	private final Integer numberOfIterationsForKeyGeneration;
	private final KeySize keySize;
	
	//XXX CRYPTO PROPERTIES
	private final Cipher cipher;
	private final SecretKeyFactory keyFactory;
	private final SecureRandom secureRandomSaltGenerator;

	//XXX CONSTRUCTOR
	/**
	 * 
	 * Constructs a reusable object with the parameters passed. 
	 * 
	 * @param numberOfIterations is the number of iteration to generate the key. Defaults to 65536.
	 * @param keySize is the size in bits of the generated key. Defaults to 256;
	 * @param charset of the characters passed in the password. Defaults to UTF-8.
	 * 
	 * @throws GeneralSecurityException
	 */
	public PBECrypto(Integer numberOfIterations, KeySize keySize, Charset charset) throws GeneralSecurityException {
		cipher = Cipher.getInstance(cipherTransformation);
		keyFactory = SecretKeyFactory.getInstance(keyFactoryAlgorithm);
		
		//from java 8 and on secureRandom is now seeded properly...
		secureRandomSaltGenerator = new SecureRandom();
		
		//number of iterations fallback handling
		if(numberOfIterations == null || numberOfIterations < 1){
			this.numberOfIterationsForKeyGeneration = defaultNumberOfIteractions;
		} else {
			this.numberOfIterationsForKeyGeneration = numberOfIterations;
		}

		//keysize fallback handling
		if(keySize == null){
			this.keySize = defaultKeySize;
		} else {
			this.keySize = keySize;
		}
		
		//charset fallback handling
		if(charset == null){
			this.charset = defaultCharset;
		} else {
			this.charset = charset;
		}
	}

	//XXX ENCRYPT METHODS
	/**
	 * 
	 * Encrypt a password returning a {@link PBEStorage} instance. 
	 * 
	 * @param password is the password to be encrypted.
	 * @return {@link PBEStorage} instance holding the encrypted data.
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception. 
	 * 
	 * @see {@link PBEStorage}
	 */
	public PBEStorage encrypt(char[] password) throws GeneralSecurityException {
		SecretKey key = deriveKey(password);

		cipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters params = cipher.getParameters();
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] ciphertext = cipher.doFinal(convertToByteArray(password));

		PBEStorage pbeStorage = new PBEStorage(iv, ciphertext, key);
		return pbeStorage;
	}
	
	/**
	 * 
	 * Derive a {@link SecretKey} from the password, number of iterations and key size passed on constructor.
	 * 
	 * @param password used in the variation. 
	 * <br> A random salt is generated using the internal {@link SecureRandom} instance.
	 * <br> Bytes from password are extracted using the {@link Charset} passed on the constructor.
	 * 
	 * @return A {@link SecretKey} generated from a {@link PBEKeySpec} formated in AES.
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	private SecretKey deriveKey(char[] password) throws GeneralSecurityException {
		byte[] salt = generateSalt();
		PBEKeySpec spec = generatePBEKeySpec(password, salt, numberOfIterationsForKeyGeneration, keySize);
		SecretKey rawKey = generateRawSecretKey(spec);
		SecretKey secretKey = formatKey(rawKey, formatKeyAlgorithm);
		return secretKey;
	}
	
	private byte[] generateSalt() {
		byte[] saltBytes = new byte[20];
		secureRandomSaltGenerator.nextBytes(saltBytes);
		return saltBytes;
	}

	private PBEKeySpec generatePBEKeySpec(char[] password, byte[] salt, int numberOfIterationsForKeyGeneration, KeySize keySize) {
		PBEKeySpec PBEKeySpec = new PBEKeySpec(password, salt, numberOfIterationsForKeyGeneration, keySize.getKeySize());
		return PBEKeySpec;
	}
	
	private SecretKey generateRawSecretKey(PBEKeySpec spec) throws InvalidKeySpecException {
		SecretKey rawSecretKey = keyFactory.generateSecret(spec);
		spec.clearPassword();
		return rawSecretKey;
	}
	
	private SecretKeySpec formatKey(SecretKey tmp, String algorithm) {
		return new SecretKeySpec(tmp.getEncoded(), algorithm);
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
	
	//XXX GETTERS
	public Charset getCharset() {
		return charset;
	}
	
	public Integer getNumberOfIterationsForKeyGeneration() {
		return numberOfIterationsForKeyGeneration;
	}
	
	public KeySize getKeySize() {
		return keySize;
	}
}
