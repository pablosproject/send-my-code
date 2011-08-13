import java.io.UnsupportedEncodingException;

import org.bouncycastle.crypto.digests.SHA256Digest;


public class SHAUtilities 
{

	public static byte[] hasSHA256(String pass){
		
		byte[] result;
		byte[]	to_digest = null ;
		SHA256Digest sha= new SHA256Digest();
		try {
			to_digest= pass.getBytes("UTF-8");
		} 
		catch (UnsupportedEncodingException e) {
			Service.log("SHA 1: errore nell'encoding. Non è possibile trasferire i dati nel formato UTF-8", 2);
			e.printStackTrace();
		}
		result=new byte[sha.getDigestSize()];
		sha.update(to_digest, 0, to_digest.length);
		
		sha.doFinal(result,0);
		return result;
		
	}
}
