package br.com.xavier.crypto.pbe;

import java.security.GeneralSecurityException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PBECryptoTest {
	
	//XXX TEST SUBJECT
	//we will use factory methods to abstract the creation of the test subject
	//private PBECrypto pbeCryto;  
	
	//XXX TEST PROPERTIES
	private char[] password;
	
	//XXX MOCK PROPERTIES
	
	//XXX INITALIZATION METHODS
	@Before
	public void setup(){
		password = "PASSWORD".toCharArray();
	}
	
	//XXX DESTROY METHODS
	@After
	public void destroy(){
		password = null;
	}
	
	//XXX TEST METHODS
	
	//EXECUTION TESTS
	@Test
	public void verifyEncryptCallOrder() throws GeneralSecurityException {
//		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
//		PBECrypto spy = Mockito.spy(pbeCrypto);
//		
//		spy.encrypt(password);
//		
//		InOrder inOrder = inOrder(spy);
//		
//		inOrder.verify(spy, times(1)).deriveKey(any(char[].class));
//		inOrder.verify(spy, times(1)).configureCipher(any(CipherMode.class), any(SecretKey.class), isNull(IvParameterSpec.class));
//		inOrder.verify(spy, times(1)).generateIV();
//		inOrder.verify(spy, times(1)).convertToByteArray(any(), any(Charset.class));
//		inOrder.verify(spy, times(1)).executeCipher(any(byte[].class));
//		inOrder.verify(spy, times(1)).generatePBEStorageInstance(any(byte[].class), any(byte[].class), any(SecretKey.class));
	}
	
	@Test
	public void verifyDeriveKeyCallOrder() throws GeneralSecurityException {
//		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
//		PBECrypto spy = Mockito.spy(pbeCrypto);
//		
//		spy.deriveKey(password);
//		
//		InOrder inOrder = inOrder(spy);
//		
//		inOrder.verify(spy, times(1)).generateSalt();
//		inOrder.verify(spy, times(1)).generatePBEKeySpec(any(char[].class), any(byte[].class), any(int.class), any(KeySize.class));
//		inOrder.verify(spy, times(1)).generateRawSecretKey(any(PBEKeySpec.class));
//		inOrder.verify(spy, times(1)).formatKey(any(SecretKey.class), any(String.class));
	}
	
	@Test
	public void verifyConfigureCipher() throws GeneralSecurityException {
		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
		
	}
	
	@Test
	public void teste(){
//		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
//		byte[] initializationVector = null;
//		byte[] cipherText = null;
//		SecretKey key = null;
		
//		PBEStorage create = pbeCrypto.create(initializationVector, cipherText, key);
//		
//		Assert.assertNotNull(pbeStorage);
//		Assert.assertEquals(derivedKey, pbeStorage.getKey());
//		Assert.assertArrayEquals(generatedIV, pbeStorage.getInitializationVector());
//		Assert.assertArrayEquals(cipherText, pbeStorage.getCipherText());
		
	}
	
	//FUNCTIONAL TESTS
	@Test
	public void mustReturnSamePassword() throws GeneralSecurityException {
		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
			
		PBEStorage pbeStorage = pbeCrypto.encrypt(password);
		char[] decrypted = pbeCrypto.decrypt(pbeStorage);
			
		Assert.assertArrayEquals(password, decrypted);
	}
}
