package demo;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.regex.Pattern;

import javax.annotation.Resource;

//import org.apache.commons.codec.binary.Hex;
//import org.apache.commons.lang.StringUtils;

import com.solab.iso8583.CustomField;
import com.solab.iso8583.IsoMessage;
import com.solab.iso8583.IsoType;
import com.solab.iso8583.MessageFactory;
import com.solab.iso8583.parse.ConfigParser;
import com.solab.iso8583.util.HexCodec;

public class SZUlinkCardVerifyProcessMac{
	
	private String privateKey;
	/**
	 * 招行62域加RB10
	 * 招行机构代码
	 * */
//	private static final String ISSUER_CODE = "03080000";
	/**
	 * 招行62域加RB10
	 * 贷记卡
	 * */
//	private static final String DEBIT_CARD_FLAG = "2";
	/**
	 * 招行62域加RB10
	 * 准贷记卡
	 * */
//	private static final String SEMI_DEBIT_CARD_FLAG = "3";
	

	private static String key_mac =null;
	
	public static void main(String[] args) throws Exception{
		//new消息工厂,读配置文件
		MessageFactory<IsoMessage> mfact=null;
		AsciiField ascii = new AsciiField();
		//创建消息模板
		IsoMessage req=null;
		try {
			mfact = ConfigParser.createFromClasspathConfig("config.xml");
			//602200000000
			
			if(key_mac==null){
				req = mfact.newMessage(0x800);
				req.setBinaryBitmap(true);//设置位图
				req.setValue(11, "022846", IsoType.NUMERIC, 6);
//				req.setValue(11, transId, IsoType.NUMERIC, 6);
				req.setValue(41, "11110112", ascii,IsoType.ALPHA, 16);
//				req.setValue(41, "11111115", ascii,IsoType.ALPHA, 16);
				req.setValue(42, "123456789100112",ascii, IsoType.ALPHA, 30);
//				req.setValue(42, "103290070111234",ascii, IsoType.ALPHA, 30);
				req.setValue(60, "00000001003",IsoType.LLLLVAR, 11);
//				req.setValue(60, "00000000003",IsoType.LLLLVAR, 11);
				req.setValue(63, "001", ascii,IsoType.LLLLVAR, 6);
				
				req.setIsoHeader("6000000000602200000000");
				int len=req.debugString().length();
				System.out.println(len);
				System.out.println(Integer.toHexString(len));
				req.setIsoHeader("00"+Integer.toHexString(len)+"6000000000602200000000");
				
			}else{
				
				req = mfact.newMessage(0x100);
				req.setBinaryBitmap(true);//设置位图
//				req.setValue(2, "6225767400707691", IsoType.LLVAR, 19);
				req.setValue(3, "330000", IsoType.NUMERIC, 6);
				req.setValue(4, "000000000007", IsoType.NUMERIC, 12);
				req.setValue(11, "022848", IsoType.NUMERIC, 6);
//				req.setValue(22, "0120",IsoType.NUMERIC,4);
				req.setValue(22, "022",IsoType.NUMERIC,3);
				req.setValue(25, "03", IsoType.NUMERIC, 2);
				req.setValue(35, "6222081206000083666D0509567890123456", IsoType.LLLVAR, 36);
				req.setValue(36, "996222081206000083666D1561560000000000000003976999236000002070000000000000000000000D000000000000D00", 
						IsoType.LLLLVAR, 99);
				req.setValue(41,"11110112",ascii,IsoType.ALPHA,16);
				req.setValue(42, "123456789100112",ascii, IsoType.ALPHA, 30);
				req.setValue(49, "156",ascii, IsoType.ALPHA, 6);
				req.setValue(60, "0100002900050", IsoType.LLLLVAR, 13);
//				req.setValue(62, "RB10NM04金·",ascii, IsoType.LLLLVAR, 72);
				req.setValue(64, "8FAF3AF3",ascii, IsoType.ALPHA, 16);
				
				req.debugString();
				System.out.println(req.debugString());
				System.out.println(req.debugString().substring(0, req.debugString().length()-16));
				//生成MAB
//				req.debugString().substring(beginIndex, endIndex);
//				String MabStr=req.debugString().substring(0, req.debugString().length()-16);
				//生成MAC
//				String encryptMac = CryptUtil.encryptMac(MabStr);
//				System.out.println(encryptMac);
				req.setIsoHeader("6000000000602200000000");
			}
			
		
//			req.updateValue(64, encryptMac);
		
			
		} catch (Exception e) {
			e.printStackTrace();
		}
//		TreeMap<String,Object> filedMap=new TreeMap<String, Object>();//报文域
//		filedMap.put("FIELD002", bean.getPriAcctNo());//主账号
//		filedMap.put("FIELD003", bean.getProcCode());//交易处理码
//		filedMap.put("FIELD011", bean.getTermSsn());//终端流水号
//		filedMap.put("FIELD022", bean.getPosEntryMdCd());//服务点输入方式码
//		filedMap.put("FIELD025", bean.getPosConCd());//服务点条件码
//		filedMap.put("FIELD041", bean.getTermIdIn());//受卡机终端标识码
//		filedMap.put("FIELD042", bean.getMchntCodeIn());//受卡方标识码（商户号），固定值
//		filedMap.put("FIELD049", bean.getTransCurrCd());//交易货币代码
//		filedMap.put("FIELD060", bean.getFld60In());//自定义域
////	filedMap.put("FIELD064", bean.getSignature());//签名
//		byte[] send=Lsy8583Util.make8583(filedMap);
//		String xmlRequest = getXmlRequest(bean);
		System.out.println(req.debugString());
//		byte[] hexDecode = HexCodec.hexDecode(str);
//		System.out.println(HexCodec.hexEncode(hexDecode, 0, hexDecode.length));
	}
	private static String getBitMap() {
		return "01100000"+"00100000"+"00000100"+"10000000"+"00000000"+"11000000"
			  +"10000000"+"00010001";
	}


	private String sign(Object bean) {
		StringBuilder sBuilder = new StringBuilder();
		String signMessage = sBuilder.toString();
		String signedMessage = sign(signMessage, privateKey.toUpperCase());
		return signedMessage.toUpperCase();
	}
	
	/**
	 * 加签
	 * 
	 * @param message
	 * @param privateKey
	 * @return
	 */
	private String sign(String message, String privateKey) {
		String signedMessage = null;

		try {
			byte[] keyBytes = hex2Byte(privateKey);
			byte[] msessageBytes = message.getBytes("GBK");
			PKCS8EncodedKeySpec pKeySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateK = keyFactory.generatePrivate(pKeySpec);
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateK);
			signature.update(msessageBytes);
//			signedMessage = Hex.encodeHexString(signature.sign());
		} catch (Exception e) {
		}
		return signedMessage;
	}
	
	/**
	 * 十六进制字符串转换为字节数组
	 *
	 * @param hexString
	 *            十六进制字符串
	 * @return 字节数组
	 */
	public static byte[] hex2Byte(String hexString) {
		if ((hexString == null) || (hexString.length() % 2 != 0)) {
			return new byte[0];
		}

		byte[] dest = new byte[hexString.length() / 2];

		for (int i = 0; i < dest.length; i++) {
			String val = hexString.substring(2 * i, 2 * i + 2);
			dest[i] = (byte) Integer.parseInt(val, 16);
		}
		return dest;
	}
	
	
	/**
	 * 记录外部渠道请求及响应时间
	 * */
	private static String getCurrentDateTime() {
		Date currentTime = new Date();
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssSSS");
		String updateTime = formatter.format(currentTime);
		return updateTime;
	}

}