package br.com.xavier.crypto.pbe;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import br.com.xavier.crypto.CipherMode;
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
	private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
	private static final String FORMAT_KEY_ALGORITHM = "AES";
	private static final int SALT_LENGTH = 20;
	
	//DEFAULT PROPERTIES
	private static final Integer DEFAULT_NUMBER_OF_ITERACTIONS = 65536;
	private static final KeySize DEFAULT_KEY_SIZE = KeySize.BITS_256;
	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
	
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
		cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		keyFactory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
		
		//from java 8 and on secureRandom is now seeded properly...
		secureRandomSaltGenerator = new SecureRandom();
		
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

	//XXX ENCRYPT METHODS
	/**
	 * 
	 * Encrypt a password returning a {@link PBEStorage} instance. 
	 * 
	 * @param password to be encrypted.
	 * @return {@link PBEStorage} instance holding the encrypted data.
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception. 
	 * 
	 * @see {@link PBEStorage}
	 */
	public PBEStorage encrypt(char[] password) throws GeneralSecurityException {
		SecretKey key = deriveKey(password);
		configureCipher(CipherMode.ENCRYPT_MODE, key, null);
		byte[] iv = generateIV();
		byte[] passwordBytes = convertToByteArray(password, charset);
		byte[] ciphertext = executeCipher(passwordBytes);
		return generatePBEStorageInstance(iv, ciphertext, key);
	}
	
	protected byte[] generateIV() throws InvalidParameterSpecException {
		AlgorithmParameters params = cipher.getParameters();
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		return iv;
	}
	
	protected PBEStorage generatePBEStorageInstance(byte[] initializationVector, byte[] cipherText, SecretKey key){
		return new PBEStorage(initializationVector, cipherText, key);
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
	protected SecretKey deriveKey(char[] password) throws GeneralSecurityException {
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
	protected byte[] generateSalt() {
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
	protected PBEKeySpec generatePBEKeySpec(char[] password, byte[] salt, int numberOfIterationsForKeyGeneration, KeySize keySize) {
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
	protected SecretKey generateRawSecretKey(PBEKeySpec spec) throws GeneralSecurityException {
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
	protected SecretKeySpec formatKey(SecretKey rawKey, String algorithm) {
		return new SecretKeySpec(rawKey.getEncoded(), algorithm);
	}

	//XXX DECRYPT METHODS
	/**
	 * 
	 * Decrypts a {@link PBEStorage} instance.
	 * 
	 * @param pbeStorage instance to be decrypted.
	 * @return <b>char[]</b> original password
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	public char[] decrypt(PBEStorage pbeStorage) throws GeneralSecurityException {
		IvParameterSpec ivParameterSpec = new IvParameterSpec(pbeStorage.getInitializationVector());
		configureCipher(CipherMode.DECRYPT_MODE, pbeStorage.getKey(), ivParameterSpec);
		byte[] decryptedContent = executeCipher(pbeStorage.getCipherText());
		return convertToCharArray(decryptedContent, charset);
	}

	//XXX CIPHER METHODS
	protected void configureCipher(CipherMode cipherMode, SecretKey key, IvParameterSpec ivSpec) throws GeneralSecurityException {
		cipher.init(cipherMode.getMode(), key, ivSpec);
	}
	
	protected byte[] executeCipher(byte[] data) throws GeneralSecurityException {
		return cipher.doFinal(data);
	}
	
	// XXX UTIL METHODS
	protected char[] convertToCharArray(byte[] byteArray, Charset charset) {
		ByteBuffer bb = ByteBuffer.wrap(byteArray);
		CharBuffer cb = charset.decode(bb);
		return cb.array();
	}

	protected byte[] convertToByteArray(char[] charArray, Charset charset) {
		CharBuffer cb = CharBuffer.wrap(charArray);
		ByteBuffer bb = charset.encode(cb);
		return bb.array();
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
