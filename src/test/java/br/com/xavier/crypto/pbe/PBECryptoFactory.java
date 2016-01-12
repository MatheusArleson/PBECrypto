package br.com.xavier.crypto.pbe;

import java.security.GeneralSecurityException;

public class PBECryptoFactory {
	
	//XXX CONSTRUCTOR
	private PBECryptoFactory(){	}

	//XXX FACTORY METHODS
	protected static PBECrypto getDefaultInstance() throws GeneralSecurityException{
		return new PBECrypto(null);
	}
	
}
