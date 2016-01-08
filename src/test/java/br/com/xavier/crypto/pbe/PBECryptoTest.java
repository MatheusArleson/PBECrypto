package br.com.xavier.crypto.pbe;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;
import org.mockito.verification.VerificationMode;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(PBECrypto.class)
public class PBECryptoTest {
	
	//XXX TEST SUBJECT
	//we will use factory methods to abstract the creation of the test subject
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
	public void destroy(){
		password = null;
	}
	
	//XXX TEST METHODS
	
	//EXECUTION TESTS
	@Test
	public void verifyEncryptCallOrder(){
		try {
			PBECrypto pbeCrypto = PBECryptoFactory.getDefaultInstance();
			PBECrypto spy = PowerMockito.spy(pbeCrypto);
			
			InOrder inOrder = Mockito.inOrder(spy);
			
			spy.encrypt(password);
			
			inOrder.verify(spy).encrypt(password);
			PowerMockito.verifyPrivate(spy, Mockito.times(1)).invoke("deriveKey", password);
			
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//FUNCTIONAL TESTS
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
