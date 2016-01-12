package br.com.xavier.crypto.pbe;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import br.com.xavier.ArraysUtil;
import br.com.xavier.crypto.enums.CipherMode;

/**
 * 
 * Class to peform Password Based Encryption (PBE)
 * 
 * @author Matheus Arleson Sales Xavier
 *
 */
public class PBECrypto {
	
	//XXX STATIC PROPERTIES
	//CRYTO PROPERTIES //TODO pass those as parameters?
	private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	
	//XXX CRYPTO PROPERTIES
	private final Cipher cipher;
	private final PBEKeyGenerator keyGenerator;

	//XXX CONSTRUCTOR
	/**
	 * 
	 * Constructs a reusable object with a default {@link PBEKeyGenerator}. 
	 * 
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	public PBECrypto() throws GeneralSecurityException {
		this(null);
	}
	
	/**
	 * 
	 * Constructs a reusable object with the parameters passed. 
	 * 
	 * @param keyGenerator is the generator for the key used in the cryto process. Defaults to the empty constructor of the {@link PBEKeyGenerator}.
	 * 
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception.
	 */
	public PBECrypto(PBEKeyGenerator keyGenerator) throws GeneralSecurityException {
		cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		
		if(keyGenerator == null){
			this.keyGenerator = new PBEKeyGenerator();
		} else {
			this.keyGenerator = keyGenerator;
		}
	}

	//XXX ENCRYPT METHODS
	/**
	 * 
	 * Encrypt a password returning a {@link PBEStorage} instance. 
	 * 
	 * @param password to be encrypted.
	 * @return {@link PBEStorage} instance holding the encrypted data.
	 * 
	 * @throws GeneralSecurityException if an exception occurs. Generic excetion wrapping the real exception. 
	 * 
	 * @see {@link PBEStorage}
	 */
	public PBEStorage encrypt(char[] password) throws GeneralSecurityException {
		SecretKey key = keyGenerator.deriveKey(password);
		configureCipher(CipherMode.ENCRYPT_MODE, key, null);
		byte[] iv = generateIV();
		byte[] passwordBytes = ArraysUtil.convertToByteArray(password, keyGenerator.getCharset());
		byte[] ciphertext = executeCipher(passwordBytes);
		return generatePBEStorageInstance(iv, ciphertext, key);
	}
	
	private byte[] generateIV() throws InvalidParameterSpecException {
		AlgorithmParameters params = cipher.getParameters();
		byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
		return iv;
	}
	
	private PBEStorage generatePBEStorageInstance(byte[] initializationVector, byte[] cipherText, SecretKey key){
		return new PBEStorage(initializationVector, cipherText, key);
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
		char[] password = ArraysUtil.convertToCharArray(decryptedContent, keyGenerator.getCharset());
		return password;
	}

	//XXX CIPHER METHODS
	private void configureCipher(CipherMode cipherMode, SecretKey key, IvParameterSpec ivSpec) throws GeneralSecurityException {
		cipher.init(cipherMode.getMode(), key, ivSpec);
	}
	
	private byte[] executeCipher(byte[] data) throws GeneralSecurityException {
		return cipher.doFinal(data);
	}
}
