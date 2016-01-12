package br.com.xavier.crypto.pbe;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import br.com.xavier.crypto.enums.KeySize;

public class PBEKeyGenerator {
	
	//XXX STATIC PROPERTIES
	//CRYTO PROPERTIES
	private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
	private static final String FORMAT_KEY_ALGORITHM = "AES";
	private static final int SALT_LENGTH = 20;
	
	//DEFAULT PROPERTIES
	private static final Integer DEFAULT_NUMBER_OF_ITERACTIONS = 65536;
	private static final KeySize DEFAULT_KEY_SIZE = KeySize.BITS_256;
	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
	
	private final SecretKeyFactory keyFactory;
	private final SecureRandom secureRandomSaltGenerator;
	
	//XXX INSTANCE PROPERTIES
	private final Charset charset;
	private final Integer numberOfIterationsForKeyGeneration;
	private final KeySize keySize;
	
	/**
	 * 
	 * Constructs a reusable object with the default parameters. 
	 * 
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	public PBEKeyGenerator() throws GeneralSecurityException {
		this(null, null, null);
	}
	
	/**
	 * 
	 * Constructs a reusable instance with the parameters passed. 
	 * 
	 * @param numberOfIterations is the number of iteration to generate the key. Defaults to 65536.
	 * @param keySize is the size in bits of the generated key. Defaults to 256;
	 * @param charset of the characters passed in the password. Defaults to UTF-8.
	 * 
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	public PBEKeyGenerator(Integer numberOfIterations, KeySize keySize, Charset charset) throws GeneralSecurityException {
		//from java 8 and on secureRandom is now seeded properly...
		secureRandomSaltGenerator = new SecureRandom();
		keyFactory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
		
		//number of iterations fallback handling
		if(numberOfIterations == null || numberOfIterations < 1){
			this.numberOfIterationsForKeyGeneration = DEFAULT_NUMBER_OF_ITERACTIONS;
		} else {
			this.numberOfIterationsForKeyGeneration = numberOfIterations;
		}

		//keysize fallback handling
		if(keySize == null){
			this.keySize = DEFAULT_KEY_SIZE;
		} else {
			this.keySize = keySize;
		}
		
		//charset fallback handling
		if(charset == null){
			this.charset = DEFAULT_CHARSET;
		} else {
			this.charset = charset;
		}
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
	public SecretKey deriveKey(char[] password) throws GeneralSecurityException {
		byte[] salt = generateSalt();
		PBEKeySpec spec = generatePBEKeySpec(password, salt, numberOfIterationsForKeyGeneration, keySize);
		SecretKey rawKey = generateRawSecretKey(spec);
		SecretKey secretKey = formatKey(rawKey, FORMAT_KEY_ALGORITHM);
		return secretKey;
	}
	
	/**
	 * 
	 * Use the internal {@link SecureRandom} instance to generated a salt.
	 * 
	 * @return <b>byte[]</b> generated salt.
	 */
	private byte[] generateSalt() {
		byte[] saltBytes = new byte[SALT_LENGTH];
		secureRandomSaltGenerator.nextBytes(saltBytes);
		return saltBytes;
	}

	/**
	 * 
	 * Creates a {@link PBEKeySpec} from the parameters passed to be used to generate {@link SecretKey}.
	 * 
	 * @param password is the password being encrypted
	 * @param salt is the random generated salt
	 * @param numberOfIterationsForKeyGeneration is the number of iterations to hash before make a key
	 * @param keySize is the number of bits the key will have
	 * @return {@link PBEKeySpec} instance
	 */
	private PBEKeySpec generatePBEKeySpec(char[] password, byte[] salt, int numberOfIterationsForKeyGeneration, KeySize keySize) {
		PBEKeySpec PBEKeySpec = new PBEKeySpec(password, salt, numberOfIterationsForKeyGeneration, keySize.getKeySize());
		return PBEKeySpec;
	}
	
	/**
	 * 
	 * Creates a raw {@link SecretKey} using the {@link PBEKeySpec} passed.
	 * 
	 * @param spec is a {@link PBEKeySpec} that will generated the raw key
	 * @return {@link SecretKey} generated from the spec
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	private SecretKey generateRawSecretKey(PBEKeySpec spec) throws GeneralSecurityException {
		SecretKey rawSecretKey = keyFactory.generateSecret(spec);
		spec.clearPassword();
		return rawSecretKey;
	}
	
	/**
	 * 
	 * Format a raw key using an algorithm.
	 * 
	 * @param rawKey is the rawKey to format.
	 * @param algorithm is and cryptography algorithm. 
	 * @return {@link SecretKeySpec} an formated key.
	 */
	private SecretKeySpec formatKey(SecretKey rawKey, String algorithm) {
		return new SecretKeySpec(rawKey.getEncoded(), algorithm);
	}
	
	//XXX GETTERS
	/**
	 * 
	 * Gets the {@link Charset} passed in the constructor.
	 * 
	 * @return {@link Charset} in use.
	 */
	public Charset getCharset() {
		return charset;
	}
	
	/**
	 * 
	 * Gets the number of iterations passed in the constructor to generate the {@link SecretKey}. 
	 * 
	 * @return <b>Integer</b> number of iterations in use.
	 */
	public Integer getNumberOfIterationsForKeyGeneration() {
		return numberOfIterationsForKeyGeneration;
	}
	
	/**
	 * 
	 * Gets the {@link KeySize} passed in the constructor.
	 * 
	 * @return {@link KeySize} in use.
	 */
	public KeySize getKeySize() {
		return keySize;
	}
}
