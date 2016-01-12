package br.com.xavier.crypto.enums;

/**
 * 
 * Enum to hold valid key sizes.
 * 
 * @author Matheus Arleson Sales Xavier
 *
 */
public enum KeySize {
	
	//XXX ENUM MEMBERS
	BITS_256(256),
	BITS_128(128);
	
	//XXX PROPERTIES
	private final int keySize;
	
	//XXX CONSTRUCTOR
	private KeySize(int keySize) {
		this.keySize = keySize;
	}
	
	//XXX GETTERS
	public int getKeySize() {
		return keySize;
	}
}
