package br.com.xavier;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

public class ArraysUtil {

	private ArraysUtil(){}
	
	public static char[] convertToCharArray(byte[] byteArray, Charset charset) {
		ByteBuffer bb = ByteBuffer.wrap(byteArray);
		CharBuffer cb = charset.decode(bb);
		return cb.array();
	}

	public static byte[] convertToByteArray(char[] charArray, Charset charset) {
		CharBuffer cb = CharBuffer.wrap(charArray);
		ByteBuffer bb = charset.encode(cb);
		return bb.array();
	}
	
}
