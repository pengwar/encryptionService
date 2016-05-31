package union.counter.api;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

public class UnionPKEncrypt {
	PublicKey publickey = null;
	public UnionPKEncrypt() {

	}
	
	public UnionPKEncrypt(String m,String e) {
		BigInteger mbig = new BigInteger(m,16);
		BigInteger ebig = new BigInteger(e, 16);

		RSAPublicKeySpec pubspec = new RSAPublicKeySpec(mbig, ebig);
		try{
		KeyFactory factory = KeyFactory.getInstance("RSA");
		publickey = factory.generatePublic(pubspec);
		System.out.println("publickey="+publickey);
		}
		catch(InvalidKeySpecException err){
			err.printStackTrace();
		}
		catch(NoSuchAlgorithmException err2){
			err2.printStackTrace();
		}
	}
	
	public String Encrypt(String plainHexStr) {
	    String cipherStr = null;
	    try {
	      byte[] plaintext = UnionStr.hex2byte(plainHexStr);
	    
	      Cipher encrypt_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	      //Cipher encrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
	      encrypt_cipher.init(Cipher.ENCRYPT_MODE, publickey);

	      /* Encrypt the secret message and store in file. */
	      byte[] ciphertext = encrypt_cipher.doFinal(plaintext);
	      cipherStr = UnionStr.byte2hex(ciphertext);
	    }
	    catch (Exception e) {
	      e.printStackTrace();
	      return null;
	    }
	    return cipherStr;
	  }
	
	
	public static void main(String args[]) {
	}
}
