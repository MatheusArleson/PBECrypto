package br.com.xavier.crypto.pbe;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import br.com.xavier.crypto.KeySize;

public class PBECryptoTest {
	
	@Test
	public void deveFuncionar(){
		try {
			PBECrypto pbeCrypto = new PBECrypto(65536, KeySize.BITS_256, Charset.forName("UTF-8"));
			
			char[] password = {'S', 'E', 'N', 'H', 'A'};
			System.out.println("#> ORIGINAL PASSWORD > " + new String(password));
			
			PBEStorage pbeStorage = pbeCrypto.encrypt(password);
			
			System.out.println("#> CIPHER TEXT	> " + toHexString(pbeStorage.getCipherText()));
			System.out.println("#> IV 			> " + toHexString(pbeStorage.getInitializationVector()));
			System.out.println("#> KEY 			> " + toHexString(pbeStorage.getKey().getEncoded()));
			
			char[] decrypted = pbeCrypto.decrypt(pbeStorage);
			System.out.println("#> DECRYPTED PASSWORD > " + new String(decrypted));
			
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private String toHexString(byte[] data){
		return new String(Hex.encodeHex(data));
	}
	
}
