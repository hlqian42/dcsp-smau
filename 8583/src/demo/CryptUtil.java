package demo;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//import com.mt.util.DateUtil;

public class CryptUtil
{
    public static final int LENGTH_PWD = 16;
    public static final String KEY_PIK = "060A3939964C8F244D793CC78A5DAF58";
//    public static final String KEY_MAK = "2222222222222222";
    public static final String KEY_MAK =   "44444444444444444444444444444444";
//    public static final String KEY_MAK =   ",,,,,,,,,,,,,,,,";
    public static final String KEY_PAN = "0000001002003004";

    /**
     * 密钥算法
     */
    private static final String KEY_ALGORITHM_3 = "DESede";

    private static final String DEFAULT_CIPHER_ALGORITHM_3 = "DESede/ECB/NoPadding";
    
    /**
     * 密钥算法
     */
    private static final String KEY_ALGORITHM = "DES";

    private static final String DEFAULT_CIPHER_ALGORITHM = "DES/ECB/NoPadding";
    
    
    private static String hexString="0123456789ABCDEF";
 
    /** 
     * 加密数据 
     * @param encryptString  注意：这里的数据长度只能为8的倍数 
     * @param encryptKey 
     * @return 
     * @throws Exception 
     */  
    public static String encrypt3DES(String encryptString, String encryptKey) throws Exception {  
        SecretKey key = new SecretKeySpec(encryptKey.getBytes("ISO8859-1"), KEY_ALGORITHM_3);  
//        SecretKey key = new SecretKeySpec(encryptKey.getBytes("UTF-8"), KEY_ALGORITHM_3);  
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM_3);  
        cipher.init(Cipher.ENCRYPT_MODE, key);  
        byte[] encryptedData = cipher.doFinal(encryptString.getBytes());  
        return Bytes2HexString(encryptedData);  
    } 
    
    /** 
     * 加密数据 
     * @param encryptString  注意：这里的数据长度只能为8的倍数 
     * @param encryptKey 
     * @return 
     * @throws Exception 
     */  
    public static String encrypt3DES(byte[] data, String encryptKey) throws Exception {  
        SecretKey key = new SecretKeySpec(encryptKey.getBytes("ISO8859-1"), KEY_ALGORITHM_3);  
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM_3);  
        cipher.init(Cipher.ENCRYPT_MODE, key);  
        byte[] encryptedData = cipher.doFinal(data);  
        return Bytes2HexString(encryptedData);  
    }
    
    /** 
     * 加密数据 
     * @param encryptString  注意：这里的数据长度只能为8的倍数 
     * @param encryptKey 
     * @return 
     * @throws Exception 
     */  
    public static String encryptDES(String encryptString, String encryptKey) throws Exception {  
//        SecretKey key = new SecretKeySpec(encryptKey.getBytes("ISO8859-1"), KEY_ALGORITHM);  
        SecretKey key = new SecretKeySpec(encryptKey.getBytes("UTF-8"), KEY_ALGORITHM);  
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);  
        cipher.init(Cipher.ENCRYPT_MODE, key);  
        byte[] encryptedData = cipher.doFinal(hex2Str(encryptString).getBytes());  
        return Bytes2HexString(encryptedData);  
    } 
    
    /** 
     * 加密数据 
     * @param encryptString  注意：这里的数据长度只能为8的倍数 
     * @param encryptKey 
     * @return 
     * @throws Exception 
     */  
    public static String encryptDES(byte[] data, String encryptKey) throws Exception {  
        SecretKey key = new SecretKeySpec(encryptKey.getBytes("ISO8859-1"), KEY_ALGORITHM);  
        Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);  
        cipher.init(Cipher.ENCRYPT_MODE, key);  
        byte[] encryptedData = cipher.doFinal(data);  
        return Bytes2HexString(encryptedData);  
    }
    
    /**
     * 密码加密封装
     * 
     * @param pwd
     *            source String.
     * @return the String is encrypted.
     */
    public static String encryptPwd(String pwd)
    {
        String returnStr = prossPwd(pwd);
        try{
            //byte[] key=toKey(KEY_PIK.getBytes());
            byte[] orb=xor(returnStr,KEY_PAN);
            //System.out.println(Bytes2HexString(orb));
            String key=hex2Str(KEY_PIK);
            if(key.length()==16){
                key=key+key.substring(0, 8);
            }
            //byte[] enb=encrypt(orb,key);
            returnStr=encrypt3DES(orb,key);
        }catch(Exception ex){
            System.out.println(ex.getMessage());
        }
        
        return returnStr;
        
    }
    
    /**
     * Mac加密封装
     * 
     * @param pwd
     *            source String.
     * @return the String is encrypted.
     */
    public static String encryptMac(String mab)
    {
        String returnStr = "";
        byte[] tmpByte=new byte[8]; //每8字节操作一下
        byte[] tmpByte1=new byte[8]; //每8字节操作一下
        byte[] mabByte=mab.getBytes();
       
        
        System.arraycopy(mabByte, 0, tmpByte1, 0, 8);//第一次copy
        //tmpByte1=HexString2Bytes(tmpByte1);
        // 构造消息摘要
        int blockNum = mabByte.length / 8;
        if(mabByte.length % 8!=0){
            blockNum=blockNum+1;
        }
        System.out.println("prev 0:"+HexCodec.hexEncode((tmpByte)));
        for (int i = 1; i <blockNum; i++) {
            if(mabByte.length<i * 8+8){
                Arrays.fill(tmpByte, (byte)0x00);
                System.arraycopy(mabByte, i * 8, tmpByte, 0, mabByte.length%8);
            }else{
                System.arraycopy(mabByte, i * 8, tmpByte, 0, 8);
            }
//            tmpByte=HexString2Bytes(tmpByte);
            System.out.println("prev:"+i+" "+HexCodec.hexEncode((tmpByte)));
            tmpByte1=xor(tmpByte1,tmpByte);
        }
        
        try
        {
            returnStr=HexCodec.hexEncode(tmpByte1);
            returnStr=HexCodec.hexEncode(returnStr.getBytes());
            
            String leftStr=returnStr.substring(0, 16);
            String rightStr=returnStr.substring(16, returnStr.length());
            
            leftStr=encrypt3DES(leftStr,hex2Str(KEY_MAK));
            byte[] mac=xor(leftStr,rightStr);
            returnStr=encrypt3DES(mac,hex2Str(KEY_MAK));
            
            returnStr=returnStr.substring(0, 8);
            
        } catch (Exception e)
        {
            e.printStackTrace();
        }
        
        return returnStr;
        
    }
    
    /**
     * 密码第一步初理
     * 
     * @param pwd
     *            source String.
     * @return the String is encrypted.
     */
    public static String prossPwd(String pwd)
    {
        String returnStr = "0";
        returnStr += pwd.length();
        returnStr += pwd;
        for (int i = pwd.length(); i < LENGTH_PWD; i++)
        {
            returnStr += "F";
        }
        //
        return returnStr;
    }

    /**
     * Encrypt String.
     * 
     * @param srcStr
     *            source String.
     * @param targetStr
     *            target String
     * @return the String is encrypted.
     */
    public static byte[] xor(String srcStr, String targetStr)
    {
        // String returnStr=null;
        // if(srcStr.length()!=targetStr.length()){
        // return returnStr;
        // }
        byte[] srcByte = HexString2Bytes(srcStr);
        byte[] tgtByte = HexString2Bytes(targetStr);
        byte[] tmpByte = new byte[srcByte.length];
        for (int i = 0; i < srcByte.length; i++)
        {
            tmpByte[i] = (byte) (srcByte[i] ^ tgtByte[i]);
            // tmpByte[i]=toHexByte(tmpByte[i]);
        }
        // returnStr=String.valueOf(tmpByte);

        return tmpByte;
    }
    
    /**
     * Encrypt byte.
     * 
     * @param srcStr
     *            byte String.  已转16进罎
     * @param targetStr
     *            byte String   已转16进罎
     * @return the String is encrypted.
     */
    public static byte[] xor(byte[] srcStr, byte[] targetStr)
    {
        // String returnStr=null;
        // if(srcStr.length()!=targetStr.length()){
        // return returnStr;
        // }
        //byte[] srcByte = HexString2Bytes(srcStr);
        //byte[] tgtByte = HexString2Bytes(targetStr);
        byte[] tmpByte = new byte[srcStr.length];
        for (int i = 0; i < srcStr.length; i++)
        {
            tmpByte[i] = (byte) (srcStr[i] ^ targetStr[i]);
            // tmpByte[i]=toHexByte(tmpByte[i]);
        }
        // returnStr=String.valueOf(tmpByte);

        return tmpByte;
    }

    // 转化十六进制编码为字符串
    public static String hex2Str(String s)
    {
        byte[] baKeyword = new byte[s.length() / 2];
        for (int i = 0; i < baKeyword.length; i++)
        {
            try
            {
                baKeyword[i] = (byte) (0xff & Integer.parseInt(
//                        s.substring(i * 2, i * 2 + 2), 16));
                s.substring(i * 2, i * 2 + 2), 32));
            } catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        try
        {
            s = new String(baKeyword,"ISO8859-1");// UTF-16le:Not
        } catch (Exception e1)
        {
            e1.printStackTrace();
        }
        return s;
    }
    
    /**
     * 
     * @param b
     *            byte[]
     * @return String
     */
    public static String Bytes2HexString(byte[] b)
    {
        String ret = "";
        for (int i = 0; i < b.length; i++)
        {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1)
            {
                hex = '0' + hex;
            }
            ret += hex.toUpperCase();
        }
        return ret;
    }

    /**
     * 将两个ASCII字符合成一个字节； 如："EF"--> 0xEF
     * 
     * @param src0
     *            byte
     * @param src1
     *            byte
     * @return byte
     */
    public static byte uniteBytes(byte src0, byte src1)
    {
        byte _b0 = Byte.decode("0x" + new String(new byte[] { src0 }))
                .byteValue();
        _b0 = (byte) (_b0 << 4);
        byte _b1 = Byte.decode("0x" + new String(new byte[] { src1 }))
                .byteValue();
        byte ret = (byte) (_b0 ^ _b1);
        return ret;
    }

    /**
     * 将指定字符串src，以每两个字符分割转换为16进制形式 如："2B44EFD9" --> byte[]{0x2B, 0x44, 0xEF,
     * 0xD9}
     * 
     * @param src
     *            String
     * @return byte[]
     */
    public static byte[] HexString2Bytes(String src)
    {
        byte[] ret = new byte[8];
        byte[] tmp = src.getBytes();
        for (int i = 0; i < 8; i++)
        {
            ret[i] = uniteBytes(tmp[i * 2], tmp[i * 2 + 1]);
        }
        return ret;
    }
    /**
     * 将指定字符串src，以每两个字符分割转换为16进制形式 如："2B44EFD9" --> byte[]{0x2B, 0x44, 0xEF,
     * 0xD9}
     * 
     * @param src
     *            String
     * @return byte[]
     */
    public static byte[] HexString2Bytes(byte[] src)
    {
        byte[] ret = new byte[8];
        byte[] tmp = src;
        for (int i = 0; i < 8; i++)
        {
            ret[i] = uniteBytes(tmp[i * 2], tmp[i * 2 + 1]);
        }
        return ret;
    }

    /*
     * 将字符串编码成16进制数字,适用于所有字符（包括中文）
     */
    public static String bin2Hex(String str)
    {
        // 根据默认编码获取字节数组
        byte[] bytes = str.getBytes();
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        // 将字节数组中每个字节拆解成2位16进制整数
        for (int i = 0; i < bytes.length; i++)
        {
            sb.append(hexString.charAt((bytes[i] & 0xf0) >> 4));
            sb.append(hexString.charAt((bytes[i] & 0x0f) >> 0));
        }
        return sb.toString().toUpperCase();
    }
    
    
    public static String genBodyKey(){
        String returnStr="";
        
        Calendar mCalendar =Calendar.getInstance();
        Date dt=mCalendar.getTime();
        
//        String tmpDt=DateUtil.getTodayString();
        
//        returnStr=tmpDt+RandomNum.createRandomString(128-tmpDt.length());
        
        return returnStr.toUpperCase();
    }
    
    
    public static String strLength(String body){
        String returnStr=""+body.length();
        while(returnStr.length()<4){
                returnStr="0"+returnStr;
        }
        return returnStr.toUpperCase();
    }
    
    /**
     * @param args
     */
    public static void main(String[] args)
    {
        // TODO Auto-generated method stub

        String password = "44000022";

        try
        {
            String pwd=bin2Hex(password);
            System.out.println(pwd);
            
        }  catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }  
        

    }
}