/*
 * create by hzh in 2009.11.5
 * ��ɽ���й�Ա��½API
 */
package union.counter.api;

//import java.io.*;
//import java.math.*;
import  java.util.Random;   
//import  java.lang.*;   

public class UnionEncPin {
	private String zek = null;
	private String zekCheckVal = null;
	private String DesKeyByPK = null;
	private String PinByPK = null;
	
	public UnionEncPin(){
	}
	
	public String getZekCheckVal() {
		return zekCheckVal;
	}

	public void setZekCheckVal(String zekCheckVal) {
		this.zekCheckVal = zekCheckVal;
	}

	int keyXorFun(byte[] buf) {
		int i = 0;
		for (i = 0; i < buf.length; i++) {
			buf[i] = keybitXorFun(buf[i]);
		}
		return 0;
	}

	byte keybitXorFun(byte buf) {
		int i = 0;
		byte ch = 0x00;
		byte val = 0x00;
		ch = (byte) (buf & (byte) 0xFE);

		for (i = 7; i > 0; i--) {
			val = (byte) (val ^ (0x01 & (ch >> i)));
		}
		val = (byte) (val ^ 1);

		val = (byte) (ch | val);

		return val;
	}

	public String gentRandKeyOdd(String str) {
		byte[] bt = UnionStr.hex2byte(str);
		this.keyXorFun(bt);
		String odd = UnionStr.byte2hex(bt);
		return odd;
	}
	
	public String makeRandomKey()
    {
		String key = null;
        String radStr = "ABCDEF0123456789";
        StringBuffer generateRandStr = new StringBuffer();
        Random rand = new Random();
        int length = 32;
        for(int i=0;i<length;i++)
        {
            int randNum = rand.nextInt(15);
            generateRandStr.append(radStr.substring(randNum,randNum+1));
        }
        key = gentRandKeyOdd(generateRandStr+"");
        zek = key;
        //System.out.println("zek=["+key+"]");
        return key;
    } 

	/**
	 * ���ܣ���������м��ܡ���������Կ�������������+��Կ������Կ������;
	 * ���룺
	 * 	pin: ����
	 *  derPK��DER��ʽ�Ĺ�Կ(�ɼ����չ�ַ�)
	 * ���أ�
	 * 		ʧ�ܣ�null
	 * 		�ɹ��������Կ�������������(32H) + ��Կ������Կ������
	 */
	
	public String Encrypt(String pin, String derPK) {
		makeRandomKey();
		if (pin == null || pin.length() == 0 || pin.length() > 16)
			return null;
		String zero32Str = "00000000000000000000000000000000";
		byte [] pinBuf = UnionStr.hex2byte(zero32Str);
		byte [] pinBytes = null;
		try{
			pinBytes = pin.getBytes(UnionCharset.getCharSetName());
		}
		catch(Exception e){
			e.printStackTrace();
			return null;
		}
		System.arraycopy(pinBytes, 0, pinBuf, 0, pinBytes.length);
		Des des = new Des(zek);
		String bufHex = UnionStr.byte2hex(pinBuf);
		String encStr = des.enc(bufHex);
		zekCheckVal = des.enc("0000000000000000");
		UnionPkForm pkForm = new UnionPkForm();
		pkForm.UnionGetPKOutOfRacalHsmCmdReturnStr(derPK);
		UnionPKEncrypt PKEncrypt = new UnionPKEncrypt(pkForm.getPkMod(),pkForm.getPkEvl());
		String zekDerFormat = "301C0410" + zek + "04089999999999999999";
		DesKeyByPK = PKEncrypt.Encrypt(zekDerFormat);
		if (DesKeyByPK == null)
			return null;
		//DesKeyByPK = encStr + DesKeyByPK;
		DesKeyByPK = DesKeyByPK;
		return DesKeyByPK;
	}
	
	/**
	 * ���ܣ���������м��ܣ��ù�Կ��Pin���Ľ��м��ܣ���䷽ʽΪPKCS1
	 * ���룺
	 * 	pin: ����
	 *  derPK��DER��ʽ�Ĺ�Կ(�ɼ����չ�ַ�)
	 * ���أ�
	 * 		ʧ�ܣ�null
	 * 		�ɹ��� ��Կ���ܵ�����
	 * */
	public String UnionEncryptPinByPK(String randomID, String pin, String derPK) {
		if (pin == null || pin.length() == 0 || pin.length() > 16)
			return null;
		
		String pinlenAndPin = String.format("%02d", pin.length()) + pin;
		String pinOfAsc = UnionStr.bcdhex_to_aschex(pinlenAndPin.getBytes());
		String idlenAndID = String.format("%02d", randomID.length()) + randomID;
		String idOfAsc = UnionStr.bcdhex_to_aschex(idlenAndID.getBytes());
		String idAndPin = idOfAsc + pinOfAsc;
		UnionPkForm pkForm = new UnionPkForm();
		pkForm.UnionGetPKOutOfRacalHsmCmdReturnStr(derPK);
		UnionPKEncrypt PKEncrypt = new UnionPKEncrypt(pkForm.getPkMod(),pkForm.getPkEvl());
		idAndPin = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"+idAndPin;
		PinByPK = PKEncrypt.Encrypt(idAndPin);
		if (PinByPK == null)
			return null;
		return PinByPK;
	}
	
	public static void  main(String[] args) throws Exception {
		UnionEncPin encPin = new UnionEncPin();
		String pin = "16654321FFFFFF";
		String random = "";
		String derPK="30818902818100C66722F55AF68B4777F4D368F5C6F8A31E15797EE36BAF1E69901A783AF51FB8AB687E6DB4BEB209E69D92638817F843CED8DFA5F8AA839D3A0DBE915C748D4DFDA732141E6CCD2965B89F0D10D7B7A5CDB6B968AC38EBE447721076C87BDD009BD9DA45021949994661729FE626CF87EE035F3BCC6CAF830941A01EFE1510C10203010001";
		String pinByPK = encPin.UnionEncryptPinByPK(random, pin, derPK);
		System.out.println("pinByPK=["+pinByPK+"]");
		//System.out.println(encPin.Encrypt("123456", derPK));
	}
	
}
