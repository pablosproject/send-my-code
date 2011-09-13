import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


public class AESCipher {

	private final int KEY_SIZE=32;
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
			this.setIV_Chiper(_IV);
		}
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(this.getKey()), this.IV_cipher);
		this.cipher.init(true, ivAndKey);
	}

	/**
	 * Inizializza l'algoritmo per decifrare. In caso cambio chiave si pu� specificare cosa fare con IV
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
	 * @throws InvalidCipherTextException si trova qualcosa di inaspettato nel messaggio. solitamente � perch� la chiave � sbagliata
	 */
	 public byte[] cipherData( byte[] data) throws InvalidCipherTextException{
		 return genericCiphering(data,this.cipher);
	 }

	 public byte[] decipherData(byte[] data) throws InvalidCipherTextException{
		 return genericCiphering(data, this.decipher);
	 }

	
	 
	 private byte[] genericCiphering(byte[] data, PaddedBufferedBlockCipher engine) throws InvalidCipherTextException {
		int size=engine.getOutputSize(data.length);
		 byte[] result=new byte[size];
		 
		 //processo i byte dell'ingresso
		 int length_processed=engine.processBytes(data, 0, data.length, result, 0);
		 int length_final=0;
		try {
			length_final = engine.doFinal(result, length_processed);
		} catch (DataLengthException e) {
			Service.log("Errore cipher, non c'� abbastanza spazio", 2);
			e.printStackTrace();
		} catch (IllegalStateException e) {
			Service.log("Errore cipher, non � inizializzato", 2);
			e.printStackTrace();
		}
		 int actualLength = length_processed + length_final;
		 
		 byte[] ciphertext = new byte[actualLength];
		 System.arraycopy(result, 0, ciphertext, 0, ciphertext.length);
		 return ciphertext;
	}

	 public int getOutSize(byte[] data){
		
		 return this.cipher.getOutputSize(data.length);
		 
	 }



	public byte [] getKey() {
		return key;
	}


	public void setKey(byte[] pass) {
		/*a volte capita che la rappresentazione in byte array della chiave
		 *eccceda di un byte la dimensione corretta. In quel caso la trasformo
		 *in un multiplo della dimensione corretta troncando l'ultimo bit
		 */
		if(pass.length>KEY_SIZE){
			//Service.log("Chiave accorciata", 2);
			byte[] _pass=Arrays.copyOfRange(pass, 0, KEY_SIZE);
			this.key=_pass;
		}
		else{
			this.key = pass;
		}
	}


	public byte [] getIV_Chiper() {
		return IV_cipher;
	}


	public void setIV_Chiper(byte [] iV) {
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

