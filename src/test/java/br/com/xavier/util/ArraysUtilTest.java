package br.com.xavier.util;

import org.junit.After;
import org.junit.Before;

public class ArraysUtilTest extends ArraysUtil {
	
	//XXX TEST PROPERTIES
	private char[] charArray;
	private byte[] byteArray;
	
	//XXX SETUP METHODS
	@Before
	public void setup(){
		String str = "TEST";
		this.charArray = str.toCharArray();
		this.byteArray = str.getBytes();
	}
	
	//XXX DESTROY METHODS
	@After
	public void destroy(){
		this.charArray = null;
		this.byteArray = null;
	}

	//XXX TEST METHODS
	
	//EXCEPTION TESTS
	public void mustThrowExeptionIfCharsetArgumentIsNull(){
		
	}
	
	public void mustThrowExeptionIfCharArrayArgumentIsNull(){
		
	}
	
	public void mustThrowExeptionIfByteArrayArgumentIsNull(){
		
	}
}
