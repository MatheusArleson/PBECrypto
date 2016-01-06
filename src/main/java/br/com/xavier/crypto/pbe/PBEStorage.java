package br.com.xavier.crypto.pbe;

import javax.crypto.SecretKey;

public class PBEStorage {
	
	//XXX STORAGE PROPERTIES
	private final byte[] initializationVector;
	private final byte[] cipherText;
	private final SecretKey key;
	
	//XXX CONSTRUCTOR
	public PBEStorage(byte[] initializationVector, byte[] cipherText, SecretKey key) {
		super();
		this.initializationVector = initializationVector;
		this.cipherText = cipherText;
		this.key = key;
	}

	//XXX GETTERS
	public byte[] getInitializationVector() {
		return initializationVector;
	}

	public byte[] getCipherText() {
		return cipherText;
	}

	public SecretKey getKey() {
		return key;
	}
}
