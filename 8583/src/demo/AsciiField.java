package demo;

import java.io.UnsupportedEncodingException;

import com.solab.iso8583.CustomField;

public final class AsciiField implements CustomField {
	
	private static String hexString="0123456789ABCDEF";

	public AsciiField() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public Object decodeField(String s) {
		// TODO Auto-generated method stub
		byte[] baKeyword = new byte[s.length() / 2];
        for (int i = 0; i < baKeyword.length; i++)
        {
            try
            {
                baKeyword[i] = (byte) (0xff & Integer.parseInt(
                        s.substring(i * 2, i * 2 + 2), 16));
            } catch (Exception e)
            {
                e.printStackTrace();
            }
        }
        try
        {
            s = new String(baKeyword,"GBK");// UTF-16le:Not
        } catch (Exception e1)
        {
            e1.printStackTrace();
        }
        return s;
	}

	@Override
	public String encodeField(Object str) {
		// TODO Auto-generated method stub
        byte[] bytes = null;
		try {
			bytes = str.toString().getBytes("GBK");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++)
        {
            sb.append(hexString.charAt((bytes[i] & 0xf0) >> 4));
            sb.append(hexString.charAt((bytes[i] & 0x0f) >> 0));
        }
        return sb.toString().toUpperCase();
	}

}
