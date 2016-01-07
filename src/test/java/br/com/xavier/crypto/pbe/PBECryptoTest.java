package br.com.xavier.crypto.pbe;

import java.security.GeneralSecurityException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PBECryptoTest {
	
	//XXX TEST SUBJECT
	//private PBECrypto pbeCryto;
	
	//XXX TEST PROPERTIES
	private char[] password;
	
	//XXX INITALIZATION METHODS
	@Before
	public void setup(){ 
		password = "PASSWORD".toCharArray(); 
	}
	
	//XXX DESTROY METHODS
	@After
	public void destroy(){}
	
	//XXX TEST METHODS
	@Test
	public void mustReturnSamePassword(){
		try {
			PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
			
			PBEStorage pbeStorage = pbeCrypto.encrypt(password);
			char[] decrypted = pbeCrypto.decrypt(pbeStorage);
			
			Assert.assertArrayEquals(password, decrypted);
			
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}
}
