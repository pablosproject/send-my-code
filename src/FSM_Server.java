import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class FSM_Server extends FSM {
	
	private enum States_Server{
		WAIT_EKE1,
		WAIT_EKE3,
	}

	private DHParameters parameter;
	private States_Server state;
	private TLV.TAG expected_tag;
	private AsymmetricCipherKeyPair key;
	private BigInteger client_pub_key;
	private BigInteger shared_key;
	private BigInteger Ra;
	public BigInteger getRb() {
		return Rb;
	}

	public void setRb(BigInteger rb) {
		Rb = rb;
	}

	private BigInteger Rb;
	

	
	public FSM_Server(DataOutputStream _out, DataInputStream _in, int _host_id, int _brother_host_id, String pass)
	{
		super(_in, _out, _host_id, _brother_host_id,pass);
	}
	
	/**
	 * Inizia il protocollo prelevando dallo stream i parametri per DH
	 */
	public boolean start() {
		
		
		try{
			BigInteger p;
			BigInteger g;
			byte[] letto_IV;
			int codice_P=TLV.getT(this.getIn());
			if (codice_P==TLV.TAG.DH_P.getCode()){
				byte[] letto_p=TLV.getV(getIn());
			    p=new BigInteger(letto_p);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perchè gli altri tag non li leggo
			}


			int codice_G=TLV.getT(getIn());
			if (codice_G==TLV.TAG.DH_G.getCode()){
				byte[] letto_g=TLV.getV(getIn());
				g=new BigInteger(letto_g);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perchè gli altri tag non li leggo
			}
			
			
			//Primo step setto i parametri DH
			this.setParameter(new DHParameters(p,g));
			

			
		}
		catch(IOException e){
			Service.log("Errore nella lettura dallo stream input, durante trasmissione" +
					"dei parametri DH e di IV.", 1);
		}
		
		byte[] vuoto= new byte[0];
		TLV conferma=new TLV(TLV.TAG.DH_PARAM_CONFIRM,vuoto);
		try {
			conferma.sendTLV(getOut());
		} catch (IOException e) {
			Service.log("Errore nell'invio conferma paramteri DH", 1);
			e.printStackTrace();
			return false;
		}
			
		this.setState(States_Server.WAIT_EKE1);
		this.setExpected_tag(TLV.TAG.EKE_1);
		return true;
	}

	public boolean nextStep() throws IOException, CipherException {
		
		int recv_tag=TLV.getT(this.getIn());
		//Prelevo il tag del pacchetto inviato, e controllo se
		//è il pacchetto che mi aspetto
		if (recv_tag==this.expected_tag.getCode())
		{
			//Implemento la logica di gestione in base allo stato in cui mi trovo
			switch(this.state){
			case WAIT_EKE1:
				return processEKE1();
			case WAIT_EKE3:
				return processEKE3();
			}	
		}
		else{
			Service.log("ERRORE, il tag ricevuto non è corretto", 0);
			return false;
		}
		return false;
	}

	/**
	 * Controlla che l'utente che richiede autenticazione sia quello corretto. 
	 * Genera la chiave condivisa
	 * Genera il pacchetto di risposta EKE2 e lo invia al client
	 * @return
	 * @throws IOException eccezoni generate dall'invio e ricezione sul socket
	 * @throws InvalidCipherTextException Eccezione generata in quanto la chiave non è corretta o il ciphertext è corrotto
	 */
	private boolean processEKE1() throws IOException, InvalidCipherTextException{
		
		//ho già controllato che il pacchetto sia di tipo EKE1
		//ora controllo che il nome della persona corrisponda a colui di cui posseggo la chiave
		byte[] _read=TLV.getV(this.getIn());

		if (TLV.getHostId(_read)==this.getBrother_host_id())
		{
			int _IV_length=this.getAES().getIV().length;
			//prelevo l'IV dall'inizio del cifrato
			byte [] _IV_recv=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE, TLV.INT_LENGTH_BYTE+_IV_length);
			//passo di generazione della chiave condivisa
			byte[] _recv_k_enc=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE+_IV_length, _read.length) ;
			Service.log("Ricezione della chiave pubblica del client", 1);
			
			//decripto la chiave pubblica ottenuta dal client
			this.getAES().initDecipher(_IV_recv, true);
			byte[] _recv_k=this.getAES().decipherData(_recv_k_enc);
			
			BigInteger pub_key= new BigInteger(_recv_k);
			Service.log("Generazione della chiave condivisa", 1);
			this.shared_key=DHUtilities.calculateDHAgreement((DHPrivateKeyParameters)key.getPrivate(), pub_key,this.getParameter());
			Service.log("Chiave condivisa: "+this.shared_key.toString(16), 1);
			
			//invio della propria chiave pubblica
			return createSendEKE2();
		}
		else{ 
			Service.log("Non è stato possibile provare l'identità dell'altro utente." +
					" Si consiglia di rilanciare il programma in modo da ottenere una connessione sicura",1);
			return false;
		}
	}
	
	/**
	 * 
	 * @return true se l'invio è corretto, false invece
	 * @throws InvalidCipherTextException Errore se la chiave non è corretta
	 */
	private boolean createSendEKE2() throws InvalidCipherTextException
	{
		//ottengo il nome dell'host da mandare
		byte[] name=Service.intToBytes(this.getHost_id());
		
		BigInteger key_public=((DHPublicKeyParameters) this.getKey().getPublic()).getY();
		byte[] key_public_arr=key_public.toByteArray();
		Service.log("Dimensione chiave pubblica:"+key_public_arr.length, 1);
		
		Service.log("Chiave pubblica: "+ key_public, 1);
		
		byte[] key_public_enc=this.getAES().cipherData(key_public_arr);
				
		BigInteger key_public_enc_print=new BigInteger(key_public_enc);
		
		Service.log("Chiave pubblica criptata: "+ key_public_enc_print, 1);
		Service.log("Initialization vector: "+new BigInteger(this.getAES().getIV()), 1);

		byte[] IV_key=Service.concatArray(this.getAES().getIV(), key_public_enc);
		byte[] name_key=Service.concatArray(name, IV_key);
		
		//creo il nuounce di B e lo mando ad A criptato
		this.Rb=Service.createNounce();
		Service.log("Nounce B: "+this.Rb,1);
		
		byte[] nounce=Rb.toByteArray();
		
		//cambio la chiave al motore AES e lo reinizializzo con un nuovo IV
		this.getAES().setKey(this.shared_key.toByteArray());
		this.getAES().initChiper(true);
		
		Service.log("Cambio di chiave avvenuto: "+ Arrays.equals(this.getAES().getKey(),this.shared_key.toByteArray()), 1);
		
		byte[] nounce_enc=this.getAES().cipherData(nounce);
		Service.log("Dimensione del nounce prima: "+nounce.length+" dimensione del nounce criptato: "+nounce_enc.length, 1);
		byte[] IV_rb=this.getAES().getIV();
		
		byte[] IV_nounce=Service.concatArray(IV_rb, nounce_enc);
		
		byte[] V=Service.concatArray(name_key, IV_nounce);

		TLV to_send=new TLV(TLV.TAG.EKE_2, V);
		Service.log("Mando il pacchetto EKE2", 0);
		try {
			to_send.sendTLV(this.getOut());
		} 
		catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		this.setState(States_Server.WAIT_EKE3);
		this.setExpected_tag(TLV.TAG.EKE_3);
		return true;
	}
		
	private boolean processEKE3() throws IOException, InvalidCipherTextException{
		
		byte[] _read=TLV.getV(this.getIn());
		
		int length_rb=this.getRb().toByteArray().length;
		
		byte[] IV_rb_ra=Arrays.copyOfRange(_read, 0, this.getAES().getIV().length);
		
		byte[] _rb_ra_enc=Arrays.copyOfRange(_read, this.getAES().getIV().length,_read.length);
		
		//inizializzo il decifratore con l'IV e decifro
		this.getAES().initDecipher(IV_rb_ra, true);
		byte[] _rb_ra=this.getAES().decipherData(_rb_ra_enc);
		
		//estraggo entrambi i nounce
		byte[] _ra=Arrays.copyOfRange(_rb_ra, length_rb, _rb_ra.length);
		byte[] _rb=Arrays.copyOfRange(_rb_ra, 0, length_rb);
		this.Ra=new BigInteger(_ra);
		BigInteger _Rb=new BigInteger(_rb);
		
		//verifico che il nuonce arrivato sia corretto
		if(_Rb.compareTo(this.getRb())==0){
			Service.log("Verifica del nounce Rb corretta.",1);
			return createSendEKE4();
		}
		else
			return false;
	}
	
	/**
	 * Cripta il nounce ricevuto da A con la chiave generata, ni modo da confermare
	 * @return
	 * @throws InvalidCipherTextException 
	 */
	private boolean createSendEKE4() throws InvalidCipherTextException {
		
		byte[] _ra=this.getRa().toByteArray();
				
		//inizializzo il cifrario con la chiave K e genero un nuovo IV
		this.getAES().initChiper(true);
		byte[] send_enc=this.getAES().cipherData(_ra);
		
		byte[] IV_nounces=Service.concatArray(this.getAES().getIV(), send_enc);
		
		TLV packet=new TLV(TLV.TAG.EKE_4,IV_nounces);
		try {
			packet.sendTLV(this.getOut());
		}
		catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		return true;
	}

	public DHParameters getParameter() {
		return parameter;
	}

	public void setParameter(DHParameters parameter) {
		this.parameter = parameter;
	}

	public States_Server getState() {
		return state;
	}

	public void setState(States_Server state) {
		this.state = state;
	}

	public TLV.TAG getExpected_tag() {
		return expected_tag;
	}

	public void setExpected_tag(TLV.TAG expected_tag) {
		this.expected_tag = expected_tag;
	}

	public AsymmetricCipherKeyPair getKey() {
		return key;
	}

	public void setKey(AsymmetricCipherKeyPair key) {
		this.key = key;
	}

	public BigInteger getRa() {
		return Ra;
	}

	public void setRa(BigInteger ra) {
		Ra = ra;
	}

	
}
