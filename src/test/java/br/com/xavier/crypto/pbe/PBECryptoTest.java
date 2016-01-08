package br.com.xavier.crypto.pbe;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;

import br.com.xavier.crypto.CipherMode;

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
		PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
		PBECrypto spy = Mockito.spy(pbeCrypto);
		
		PBEStorage pbeStorage = spy.encrypt(password);
		
		InOrder inOrder = Mockito.inOrder(spy);
		
		inOrder.verify(spy).deriveKey(password);
		inOrder.verify(spy).configureCipher(Mockito.any(CipherMode.class), Mockito.any(SecretKey.class), Mockito.isNull(IvParameterSpec.class));
		inOrder.verify(spy).generateIV();
		inOrder.verify(spy).convertToByteArray(password, pbeCrypto.getCharset());
		//inOrder.verify(spy).executeCipher(passwordBytes);
		
		
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
