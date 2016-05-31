package union.counter.api;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;
import java.io.*;

public class UnionStr {
	
	public static String byte2hex(byte[] b) { //二行制转字符串
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
            if (n < b.length - 1) {
                hs = hs + "";
            }
        }
        return hs.toUpperCase();
    }

     public static byte[] hex2byte(String str) { //字符串转二进制
        int len = str.length();
        String stmp = null;
        byte bt[] = new byte[len / 2];
        for (int n = 0; n < len / 2; n++) {
            stmp = str.substring(n * 2, n * 2 + 2);
            bt[n] = (byte) (java.lang.Integer.parseInt(stmp, 16));
        }
        return bt;
    }
     
     // 补0x00到8的倍长
     public static final byte [] AllRightZreoTo8Multiple(byte []bytes) 
     {
         if(bytes.length%8 == 0)
             return bytes;
         int len = bytes.length + 8 - bytes.length%8;
         byte [] newbytes = new byte[len];
         for(int i=0;i<len;i++)
             newbytes[i] = 0;
         System.arraycopy(bytes, 0, newbytes, 0, bytes.length);
         return newbytes;
     }
     
     //除去补充的0x00
     public static final byte [] AllTrimZreoFrom8Multiple(byte []bytes) 
     {
         int zreoCount = 0;
         if (bytes.length == 0)
         	return bytes;
         
         for(int i=bytes.length-1;i>=bytes.length-8;i--)
         {
         	if (bytes[i] != 0x0)
         		break;
             zreoCount++;
         }
         byte [] newbytes = new byte[bytes.length-zreoCount];
         System.arraycopy(bytes, 0, newbytes, 0, bytes.length-zreoCount);
         return newbytes;
     }
     
     public static final String bcdhex_to_aschex(byte[] bcdhex) {
 		byte[] aschex = { 0, 0 };
 		String res = "";
 		String tmp = "";
 		for (int i = 0; i < bcdhex.length; i++) {
 			aschex[1] = hexLowToAsc(bcdhex[i]);
 			aschex[0] = hexHighToAsc(bcdhex[i]);
 			tmp = new String(aschex);
 			res += tmp;
 		}
 		return res;
 	}

 	public static final byte[] bcdhex_to_aschex(byte[] bcdhex, int len) {
 		byte[] aschex = new byte[len * 2];

 		for (int i = 0; i < len; i++) {
 			aschex[2 * i] = hexHighToAsc(bcdhex[i]);
 			aschex[2 * i + 1] = hexLowToAsc(bcdhex[i]);
 		}
 		return aschex;
 	}

 	public static byte[] aschex_to_bcdhex(String aschex) {
 		byte[] aschexByte = aschex.getBytes();
 		int j = 0;
 		if (aschexByte.length % 2 == 0) {
 			j = aschexByte.length / 2;
 			byte[] resTmp = new byte[j];
 			for (int i = 0; i < j; i++) {
 				resTmp[i] = ascToHex(aschexByte[2 * i], aschexByte[2 * i + 1]);
 			}
 			return resTmp;

 		} else {
 			j = aschexByte.length / 2 + 1;
 			byte[] resTmp = new byte[j];
 			for (int i = 0; i < j - 1; i++) {
 				resTmp[i] = ascToHex((byte) aschexByte[2 * i],
 						(byte) aschexByte[2 * i + 1]);
 			}
 			resTmp[j - 1] = ascToHex((byte) aschexByte[2 * (j - 1)], (byte) 0);
 			return resTmp;
 		}

 	}

 	public static byte[] aschex_to_bcdhex(byte[] aschex, int len) {
 		int i, j;
 		if (len % 2 == 0) {
 			j = len / 2;
 		} else {
 			j = len / 2 + 1;
 		}
 		byte[] bcdhex = new byte[j];
 		for (i = 0; i < j; i++) {
 			bcdhex[i] = ascToHex(aschex[2 * i], aschex[2 * i + 1]);
 		}
 		return bcdhex;

 	}
 	private static byte hexLowToAsc(byte xxc) {
		xxc &= 0x0f;
		if (xxc < 0x0a)
			xxc += '0';
		else
			xxc += 0x37;
		return (byte) xxc;
	}

	private static byte hexHighToAsc(int xxc) {
		xxc &= 0xf0;
		xxc = xxc >> 4;
		if (xxc < 0x0a)
			xxc += '0';
		else
			xxc += 0x37;
		return (byte) xxc;
	}

	private static byte ascToHex(byte ch1, byte ch2) {
		byte ch;
		if (ch1 >= 'A')
			ch = (byte) ((ch1 - 0x37) << 4);
		else
			ch = (byte) ((ch1 - '0') << 4);
		if (ch2 >= 'A')
			ch |= (byte) (ch2 - 0x37);
		else
			ch |= (byte) (ch2 - '0');
		return ch;
	}

	public static final byte[] arraycat(byte[] buf1, byte[] buf2) {
		byte[] bufret = null;

		int len1 = 0;
		int len2 = 0;

		if (buf1 != null)
			len1 = buf1.length;
		if (buf2 != null)
			len2 = buf2.length;

		if (len1 + len2 > 0)
			bufret = new byte[len1 + len2];
		if (len1 > 0)
			System.arraycopy(buf1, 0, bufret, 0, len1);
		if (len2 > 0)
			System.arraycopy(buf2, 0, bufret, len1, len2);
		return bufret;
	}

	public static final byte[] AscToBcd(String source) {

		if (source == null)
			return null;
		int len = source.length();
		len = len / 2;
		byte[] dest = new byte[len];

		for (int i = 0; i < len; i++) {
			char c1 = source.charAt(i * 2);
			char c2 = source.charAt(i * 2 + 1);
			byte b1, b2;
			if ((c1 >= '0') && (c1 <= '9'))
				b1 = (byte) (c1 - '0');
			else if ((c1 >= 'a') && (c1 <= 'z'))
				b1 = (byte) (c1 - 'a' + 0x0a);
			else
				b1 = (byte) (c1 - 'A' + 0x0a);

			if ((c2 >= '0') && (c2 <= '9'))
				b2 = (byte) (c2 - '0');
			else if ((c2 >= 'a') && (c2 <= 'z'))
				b2 = (byte) (c2 - 'a' + 0x0a);
			else
				b2 = (byte) (c2 - 'A' + 0x0a);

			dest[i] = (byte) ((b1 << 4) | b2);
		}
		return dest;
	}
	/*
	 * 功能：返回a和b异或的结果out
	 */
	public static final String UnionXOR(String a, String b)
	{
		if (a.length() != b.length())
			return null;
		
		byte [] aBuf = aschex_to_bcdhex(a);
		byte [] bBuf = aschex_to_bcdhex(b);

		byte [] outBuf = new byte[aBuf.length];
		for (int j=0; j<aBuf.length; j++)
			outBuf[j] = (byte)(aBuf[j] ^ bBuf[j]);
		
		return bcdhex_to_aschex(outBuf);
	}

	public static void  main(String[] args) throws Exception {
		UnionStr str = new UnionStr();
		String aaa = "654321";
		String bbb = "123456";
		
		String result = str.UnionXOR(aaa,bbb);
		
		System.out.println("result=["+result+"]");
	}
}
