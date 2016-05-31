package union.counter.api;

import javax.crypto.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.SecretKeyFactory;   
import javax.crypto.spec.DESedeKeySpec;   
import java.security.InvalidKeyException;   
import java.security.spec.InvalidKeySpecException;   
import union.counter.api.*;

/**
 * DES加密的，文件中共有两个方法,加密、解密 加密后的数据：Des.createEncryptor(Test);
 * 解密后的数据：Des.createDecryptor(Des.createEncryptor(Test));
 */
public class Des {
	private String Algorithm = "DESede";
	private byte[] inkey = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
	private KeyGenerator keygen;
	private SecretKey deskey;
	private Cipher c;


	/**
	 * 初始化 DES 实例
	 */
	public Des() {
		init();
	}

	/**
	 * 初始化 DES 实例,初始参数为HEXKey
	 */
	public Des(String hexkey) {
		String key = hexkey;
		if (hexkey.length() == 16)
		{
			key += hexkey + hexkey;
		}
		else if (hexkey.length() == 32) {
			key += hexkey.substring(0,16);
		}
		inkey = UnionStr.hex2byte(key);
		init();
	}

	public void init() {
		Security.addProvider(new com.sun.crypto.provider.SunJCE());
		try {
			keygen = KeyGenerator.getInstance(Algorithm);
			deskey = new SecretKeySpec(inkey, Algorithm);
			c = Cipher.getInstance("DESede/ECB/NOPADDING");
		} catch (NoSuchAlgorithmException ex) {
			ex.printStackTrace();
		} catch (NoSuchPaddingException ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * 对 byte数组 进行加密
	 * 
	 * @param str
	 *            要加密的数据
	 * @return 返回加密后的 byte 数组
	 */
	public byte[] createEncryptor(byte [] tb) {
		byte[] cipherByte = null;
		try {
			c.init(Cipher.ENCRYPT_MODE, deskey);
			cipherByte = c.doFinal(UnionStr.AllRightZreoTo8Multiple(tb));
		} catch (java.security.InvalidKeyException ex) {
			ex.printStackTrace();
		} catch (javax.crypto.BadPaddingException ex) {
			ex.printStackTrace();
		} catch (javax.crypto.IllegalBlockSizeException ex) {
			ex.printStackTrace();
		}
		catch(Exception ex){
			ex.printStackTrace();
		}
		return cipherByte;
	}

	/**
	 * 对 Byte 数组进行解密
	 * 
	 * @param tb
	 *            要解密的数据
	 * @return 返回解密后的 byte
	 */
	public byte[] createDecryptor(byte[] tb) {
		byte[] plainByte = null;
		byte[] plainByteTrim = null;
		try {
			c.init(Cipher.DECRYPT_MODE, deskey);
			plainByte = c.doFinal(tb);
		} catch (java.security.InvalidKeyException ex) {
			ex.printStackTrace();
		} catch (javax.crypto.BadPaddingException ex) {
			ex.printStackTrace();
		} catch (javax.crypto.IllegalBlockSizeException ex) {
			ex.printStackTrace();
		}
		plainByteTrim = UnionStr.AllTrimZreoFrom8Multiple(plainByte);
		return (plainByteTrim);
	}

	/**
	 * 对 HexStr 数组进行解密
	 * 
	 * @param HexStr
	 *            要解密的数据
	 * @return 返回解密后的 HexStr
	 */
	public String dec(String HexStr) {
		return UnionStr.byte2hex(createDecryptor(UnionStr.hex2byte(HexStr)));
	}

	/**
	 * 对 HexStr 进行加密
	 * 
	 * @param HexStr
	 *            要加密的数据
	 * @return 返回加密后的 HexStr
	 */
	public String enc(String HexStr) {
		return UnionStr.byte2hex(createEncryptor(UnionStr.hex2byte(HexStr)));
	}
	
	/**
	 * 对 Str可见字符串 进行加密
	 * 
	 * @param str
	 *            要加密的数据
	 * @return 返回加密后的 HexStr
	 */
	public String encStr2Hex(String str)
	{
		String HexStr = "";
		try{
		 HexStr = UnionStr.byte2hex(str.getBytes(UnionCharset.getCharSetName()));	
		}catch(Exception e){
			return HexStr;
		}
		return enc(HexStr);
	}
	
	/**
	 * 对 HexStr 数组进行解密
	 * 
	 * @param HexStr
	 *            要解密的数据
	 * @return 返回解密后的 HexStr
	 */
	public String decHex2Str(String HexStr) {
		String decHexstr = dec(HexStr);
		String str = "";
		try{
		str = new String(UnionStr.hex2byte(decHexstr),UnionCharset.getCharSetName());
		}catch(Exception e)
		{
			return str;
		}
		return str;
	}
	
	
	public static void main(String[] args) 
	{
		System.out.println("hello world!");
		String encStr = "";
		String buf = "FAB2FCD7268C832C";
		System.out.println("明文1:["+buf+"]");		
		Des des = new Des("B4011F49527A00964CE3A961D82A9B40");
		encStr = des.enc(buf);
		System.out.println("密文1:["+encStr+"]");
		buf = des.dec(encStr);
		System.out.println("明文1:["+buf+"]");
		

		buf = "linyr";
		String bufHex = UnionStr.byte2hex(buf.getBytes());
		System.out.println("明文2:["+bufHex+"]");
		//bufHex = "05"+bufHex;
		//App.strAddZero(bufHex,16);
		String encHex = des.enc(bufHex);
		
		System.out.println("密文Hex2:["+encHex+"]");
		String plaintxt = des.decHex2Str(encHex);
		System.out.println("明文2:=["+plaintxt+"]");
		
	}
		
}
	
