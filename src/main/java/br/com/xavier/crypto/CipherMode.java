package br.com.xavier.crypto;

import javax.crypto.Cipher;

/**
 * 
 * Enum to hold {@link Cipher} modes.
 * 
 * @author Matheus Arleson Sales Xavier
 *
 */
public enum CipherMode {

	//XXX ENUM MEMBERS
	ENCRYPT_MODE(Cipher.ENCRYPT_MODE),
	DECRYPT_MODE(Cipher.DECRYPT_MODE);
	
	//XXX ENUM MEMBER PROPERTIES
	private final int mode;
	
	//XXX CONSTRUCTOR
	private CipherMode(int mode) {
		this.mode = mode;
	}
	
	//XXX GETTERS
	public int getMode() {
		return mode;
	}
}
