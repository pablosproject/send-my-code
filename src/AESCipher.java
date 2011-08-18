import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


public class AESCipher {

	
	private byte [] key;
	private byte [] IV_cipher;
	private byte [] IV_decipher;
	private PaddedBufferedBlockCipher cipher;
	private PaddedBufferedBlockCipher decipher;
	
	public AESCipher(String pass){
		
		this.key=SHAUtilities.hasSHA256(pass);
	}
	
	/**
	 * Inizializza l'algoritmo per cifrare simmetricamente, in caso di cambio chiave si risetta
	 * @param new_iv
	 */
	public void initChiper(boolean new_iv){
		
		this.cipher=new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
		if(new_iv){
			byte[] _IV=new byte[this.cipher.getBlockSize()];
			SecureRandom rand=new SecureRandom();
			rand.nextBytes(_IV);
			this.setIV(_IV);
		}
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(this.getKey()), this.IV_cipher);
		this.cipher.init(true, ivAndKey);
	}

	/**
	 * Inizializza l'algoritmo per decifrare. In caso cambio chiave si può specificare cosa fare con IV
	 * @param IV
	 * @param new_iv
	 */
	public void initDecipher(byte[] IV, boolean new_iv){
		
		this.setDecipher(new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine())));
		if(new_iv)
			this.setIV_decipher(IV);
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(this.getKey()), this.IV_decipher);
		this.decipher.init(false, ivAndKey);
	}
		
	/**
	 * Cifra i dati passati usando il block cipher passato a parametro
	 * @param cipher il motore di cifrature
	 * @param data i dati da cifrare
	 * @return un bytearray con i dati cifrati
	 */
	 public byte[] cipherData( byte[] data){
		 return genericCiphering(data,this.cipher);
	 }

	 public byte[] decipherData(byte[] data){
		 return genericCiphering(data, this.decipher);
	 }

	
	 
	 private byte[] genericCiphering(byte[] data, PaddedBufferedBlockCipher engine) {
		int size=engine.getOutputSize(data.length);
		 byte[] result=new byte[size];
		 
		 //processo i byte dell'ingresso
		 int length_processed=engine.processBytes(data, 0, data.length, result, 0);
		 int length_final=0;
		try {
			length_final = engine.doFinal(result, length_processed);
		} catch (DataLengthException e) {
			Service.log("Errore cipher, non c'è abbastanza spazio", 2);
			e.printStackTrace();
		} catch (IllegalStateException e) {
			Service.log("Errore cipher, non è inizializzato", 2);
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			Service.log("Errore cipher, non trovo il padding", 2);
			e.printStackTrace();
		}
		 int actualLength = length_processed + length_final;
		 
		 byte[] ciphertext = new byte[actualLength];
		 System.arraycopy(result, 0, ciphertext, 0, ciphertext.length);
		 return ciphertext;
	}




	public byte [] getKey() {
		return key;
	}


	public void setKey(String pass) {
		this.key = SHAUtilities.hasSHA256(pass);
	}


	public byte [] getIV() {
		return IV_cipher;
	}


	public void setIV(byte [] iV) {
		IV_cipher = iV;
	}

	public byte [] getIV_decipher() {
		return IV_decipher;
	}

	public void setIV_decipher(byte [] iV_decipher) {
		IV_decipher = iV_decipher;
	}

	public PaddedBufferedBlockCipher getDecipher() {
		return decipher;
	}

	public void setDecipher(PaddedBufferedBlockCipher decipher) {
		this.decipher = decipher;
	}
}

