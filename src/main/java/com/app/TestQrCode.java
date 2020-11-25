package com.app;

import java.io.UnsupportedEncodingException;

import sun.misc.BASE64Decoder;

public class TestQrCode {
	
	public static void main(String[] args) throws UnsupportedEncodingException, Exception {
		
		String sign = null;
		
		 try {
			 BASE64Decoder decoder = new BASE64Decoder();
		     String[]  splitSignedText = sign.split("\\.");
		     String decodedSigned =new String(decoder.decodeBuffer(splitSignedText[0]));
		     decodedSigned = decodedSigned +"\n Content:"+(new String(decoder.decodeBuffer(splitSignedText[1])));
		     
		     decodedSigned.replaceAll("\\\"", "\"");
		     System.out.println("\nDecoded Text:" + decodedSigned);
		   } catch (Exception ex) {
		     
		    }
	}
	

}
