//create by linxj 20120514
package union.counter.api;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.Cipher;

public class UnionVKDecrypt {
	PrivateKey privateKey = null;
	public UnionVKDecrypt() {
		this.privateKey = null;
	}
	
	public UnionVKDecrypt(String m,String e) {
		BigInteger mbig = new BigInteger(m,16);
		BigInteger ebig = new BigInteger(e, 16);

		RSAPrivateKeySpec pubspec = new RSAPrivateKeySpec(mbig, ebig);
		try{
			KeyFactory factory = KeyFactory.getInstance("RSA");
			privateKey = factory.generatePrivate(pubspec);
		}
		catch(InvalidKeySpecException err){
			err.printStackTrace();
		}
		catch(NoSuchAlgorithmException err2){
			err2.printStackTrace();
		}
	}
	/*���ܣ���ʼ��˽Կ
	 * m	ģ����Կ��
	 * e	ָ��˽Կ��
	 * ���ڣ�20120515
	 * auto:linxj
	 * */
	public void UnionInitVK(String m,String e) {
		BigInteger mbig = new BigInteger(m,16);
		BigInteger ebig = new BigInteger(e, 16);

		RSAPrivateKeySpec pubspec = new RSAPrivateKeySpec(mbig, ebig);
		try{
			KeyFactory factory = KeyFactory.getInstance("RSA");
			privateKey = factory.generatePrivate(pubspec);
		}
		catch(InvalidKeySpecException err){
			err.printStackTrace();
		}
		catch(NoSuchAlgorithmException err2){
			err2.printStackTrace();
		}
	}
	
	/*���ܣ������ù�Կ���ܵ����
	 * encHexStr	��Կ���ܵ�����
	 * ���ڣ�20120514
	 * auto:linxj
	 * */
	public String Decrypt(String encHexStr) {
	    String cipherStr = null;
	    try {
	    	byte[] enctext = UnionStr.hex2byte(encHexStr);
	    	Cipher encrypt_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	      //Cipher encrypt_cipher = Cipher.getInstance("RSA/ECB/NoPadding");
	    	encrypt_cipher.init(Cipher.DECRYPT_MODE, privateKey);

	    	/* Decrypt the secret message and store in file. */
	    	byte[] ciphertext = encrypt_cipher.doFinal(enctext);
	     
	    	cipherStr = UnionStr.byte2hex(ciphertext);
	    }catch(Exception e) {
	      e.printStackTrace();
	      return null;
	    }
	    return cipherStr;
	  }
	
	/*���ܣ����ܻ�ȡ��Կ����Ӧ�ļ��ܻ�ָ��ΪGK
	 * m			ģ
	 * e			ָ��
	 * encHexStr	����
	 * ���ڣ�20120515
	 * auto:linxj
	 * */
	public String GetDesKeyFromBlock(String m, String e, String encHexStr){
		String deskey = null;
		if((encHexStr == null) || (encHexStr.length() == 0)){
			return null;
		}
		UnionInitVK(m,e);
		String plainText = Decrypt(encHexStr);
		if(plainText.substring(0, 8).equals("30140408")){
			deskey = plainText.substring(8, 24);
		}
		if(plainText.substring(0, 8).equals("301C0410")){
			deskey = plainText.substring(8, 40);
		}
		
		return deskey;
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		//String m = "C6F5E54443994CA6517F90DB3D63747C0E4B398EF59ABC1A1C36CFF1A7D97AD1E0E090FDC66A3011AE99897EB97C41B93A6C2A09ED1AAEDEA12971EB918137CDD988C960694081473E00808C6DDC73021D3CCBF264F162422109DDF5BD50D74308FC9A709F43384B8996F9FAEAC613599C0A5ED77CB2657652AB70566C48272F";
		String m = "E742520938ABEECBC956DB0248ADBBDC8BAE3AEDA516184E78B0143FE7D53CBF00D6922599FE46ABCB964220545557AF90B6C4A676AD6186F42AF82732717D0D54118B2AEB665A45A53EFB78CF5FC9FD9A6D8B5872074FD3314951E3736D9009C18B3E24EC5BCDBBAFE8C6670129498908E372FB4E2EC68E371A347433344515";
		//String e = "C3D4A01732DA1F01CD51DC488F01E7537BD63B0F255B6A2DE0FB6A6D97228EAB29C69FAFC9AE1726304EDB70AA2D4D9B7D8F9D492BE189A183CB815FB656138F836989ACD1CE755C8D562F205D145F2D5F821E12DF717FAE16373FC9CDAC946C4F5C51627C0424A690F9B80B4F1EC633C2FC69943CC3F79D607E456CDBB92D71";
		String e = "23B14DBE149C1CC02134219B49A25EE35C3FA8E2B2DF25233F6755C8C33C5B22D3BB4A55395E508405690C8DB6D671312CB1B8CA4478E01B9725E6A50E190C06AE78BB3217DA8091BB8C14939CB24CC6A3B28F5E4F4ECA9015C66AB9B6DA3AC4EB01BA4D81893C44F6AE4594B757506EDD6D7FAC6852227B07A9641A86E7E2C5";
		//String encHexStr = "3DF68FE8B68D493576EE81F5141F3A95B0698CCBDB5A7DC96900E3F2C218C8A0A534B3D358C0338C18ABFDE411C175DDC7D4AFAC9A931D23EC009F6F26B3165DD094F93BE1E32CA0532A26001559A1AEC61AC36DE8241AC7C586C25F2731FC0A3E6DCCD1950EF1E214976FDB2B5EFEF2C56B85F378CEAEE2B2D8A2BD4D8B54D6";
		UnionVKDecrypt vkDecrypt = new UnionVKDecrypt(m,e);
		String encHexStr = "9B309CF565EF5CB9F724B95A30C19C04A953117A6ADF51966FD390FBCD316698B3CCFE9F48EDA9FAC18D17FE5050DF53B488824A26386C747D685751E01707B1256B38EC91E85576CF219E4A87398299DD35AE2B36773D8216C5F014E9D99AE8EEA5931B51ED85360F5C24521CFAC8B16D377E3C13C6CACAD92AEE8DD103914A";
		String deskey = vkDecrypt.Decrypt(encHexStr);
		System.out.println("deskey="+deskey);
	}
}
