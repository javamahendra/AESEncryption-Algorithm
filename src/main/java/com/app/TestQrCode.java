package com.app;

import java.io.UnsupportedEncodingException;

import sun.misc.BASE64Decoder;

public class TestJwtToken {
	
	public static void main(String[] args) throws UnsupportedEncodingException, Exception {
		
		String jwt = null;
		
		 try {
                     BASE64Decoder decoder = new BASE64Decoder();
		     String[]  splitSignedText = jwt.split("\\.");
		     String decodedSigned =new String(decoder.decodeBuffer(splitSignedText[0]));
		     decodedSigned = decodedSigned +"\n Content:"+(new String(decoder.decodeBuffer(splitSignedText[1])));
		     
		     decodedSigned.replaceAll("\\\"", "\"");
		     System.out.println("\nDecoded Text:" + decodedSigned);
		   } catch (Exception ex) {
		     System.out.println(ex.getMessage());
		   }
	}
	

}
