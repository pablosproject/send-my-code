import java.awt.RenderingHints.Key;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class FSM_Client extends FSM {

	private enum States_Client{
		WAIT_DH_PARAM_CONFIRM,
		WAIT_EKE2,
		WAIT_EKE4
	}
	
	private States_Client state;
	private TLV.TAG expected_tag;
	private AsymmetricCipherKeyPair DH_key;
	private BigInteger server_pub_key;
	private BigInteger shared_key;
	private BigInteger Rb;
	private BigInteger Ra;
	
	public FSM_Client(DataOutputStream _out, DataInputStream _in, AsymmetricCipherKeyPair _key, int _host_id, int _brother_host_id, String pass){
		
		super(_in, _out,_host_id,_brother_host_id,pass);
		this.DH_key=_key;
	}
	/**
	 * Metodo che inizia il protocollo. Invia i parametri DH pubblici all'altro host.
	 * La sequenza di invio è P->Q->G
	 * @return true, se l'invio è andato correttamente e si attende il prossimo passo, false se non 
	 * funziona qualcosa
	 */
	public boolean start() {
		
		//ESTRAGGO dalla chiave pubblica i parametri per il generatore di chiavi DH e li invio
		DHPublicKeyParameters public_param=(DHPublicKeyParameters) DH_key.getPublic();
		BigInteger p=public_param.getParameters().getP();
		BigInteger g=public_param.getParameters().getG();
		
		TLV p_tlv=new TLV(TLV.TAG.DH_P,p.toByteArray());
		TLV g_tlv=new TLV(TLV.TAG.DH_G,g.toByteArray());
		
		try {
			p_tlv.sendTLV(getOut());
			g_tlv.sendTLV(getOut());
		} 
		catch (IOException e) {
			Service.log("Errore nell'invio dei parametri DH", 0);
			e.printStackTrace();
			return false;
		}
		
		this.state=States_Client.WAIT_DH_PARAM_CONFIRM;
		this.setExpected_tag(TLV.TAG.DH_PARAM_CONFIRM);
		return true;
	}

	
	public boolean nextStep() throws IOException {
		
			int recv_tag=TLV.getT(this.getIn());
			//Prelevo il tag del pacchetto inviato, e controllo se
			//è il pacchetto che mi aspetto
			if (recv_tag==this.expected_tag.getCode())
			{
				//Implemento la logica di gestione in base allo stato in cui mi trovo
				switch(this.state){
				case WAIT_DH_PARAM_CONFIRM:
					this.getIn().readInt();
					return createSendEKE1();
				case WAIT_EKE2:
					return processEKE2();
				case WAIT_EKE4:
					return processEKE4();
				}
			}
			else{
				Service.log("ERRORE, il tag ricevuto non è corretto", 0);
				return false;
			}
			return false;
	}

	
	/**
	 * Genera la chiave pubblica e la invia, serializzata con il nome. La chiave pubblica viene criptata con la chiave condivisa
	 * @return true, se il passo è stato compiuto correttamente. false altrimenti
	 */
	private boolean createSendEKE1(){
		
		byte[] name=Service.intToBytes(getHost_id());
		BigInteger key_public=((DHPublicKeyParameters) DH_key.getPublic()).getY();
		byte[] key_public_arr=key_public.toByteArray();
		Service.log("Dimensione chiave condivisa: "+key_public_arr.length,0);
		Service.log("Chiave pubblica: "+ key_public, 0);
		
		byte[] key_public_enc=this.getAES().cipherData(key_public_arr);
				
		BigInteger key_public_enc_print=new BigInteger(key_public_enc);
		Service.log("Chiave pubblica criptata: "+ key_public_enc_print, 0);
		Service.log("Initialization vector: "+new BigInteger(this.getAES().getIV()), 1);
		
		//creo il contenuto informativo cifrato, mando IV+chiave cifrata
		byte[] IV_key=Service.concatArray(this.getAES().getIV(), key_public_enc);
		
		byte[] T=Service.concatArray(name, IV_key);
		
		TLV to_send=new TLV(TLV.TAG.EKE_1, T);
		Service.log("Mando il pacchetto EKE1", 0);
		try {
			to_send.sendTLV(this.getOut());
		} 
		catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		this.state=States_Client.WAIT_EKE2;
		this.expected_tag=TLV.TAG.EKE_2;
		
		return true;
	}
	
	/**
	 * Controlla l'identità dell'host B.
	 * Genera la chiave di sessione.
	 * Invia il pacchetto di conferma al server
	 * @return
	 * @throws IOException 
	 */
	private boolean processEKE2() throws IOException{
		
		byte[] _read=TLV.getV(this.getIn());
		
		if (TLV.getHostId(_read)==this.getBrother_host_id()){

			//Genero il nounce
			this.setRa(Service.createNounce());
			
			//Calcolo le lunghezze per leggere il pacchetto
			int nounce_length=this.getAES().getOutSize(this.Ra.toByteArray());
			int IV_length=this.getAES().getIV().length;
			
			int IV_key_length=_read.length-TLV.INT_LENGTH_BYTE-IV_length-nounce_length;
			//								sottraggo il nome host   sottraggo il nounce criptato 
			//ricevo la chiave condivisa
			byte[] _recv_IV_pk=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE, (IV_key_length+TLV.INT_LENGTH_BYTE));
			Service.log("Ricezione della chiave pubblica del Server", 0);
			
			//estraggo IV e inizializzo il motore per decriptare
			byte[] IV_pubkey=Arrays.copyOfRange(_recv_IV_pk, 0, IV_length);
			this.getAES().initDecipher(IV_pubkey, true);
			
			//estraggo e decifro la chiave pubblica di B
			byte[] pubkey_enc=Arrays.copyOfRange(_recv_IV_pk, IV_length, _recv_IV_pk.length);
			byte[] pubkey=this.getAES().decipherData(pubkey_enc);
			
			//genero la chiave condivisa
			BigInteger pub_key= new BigInteger(pubkey);
			Service.log("Generazione della chiave condivisa", 0);
			this.shared_key=DHUtilities.calculateDHAgreement((DHPrivateKeyParameters)this.getDH_key().getPrivate(), pub_key,(DHParameters) ((DHKeyParameters) this.getDH_key().getPublic()).getParameters());
			Service.log("Chiave condivisa: \n"+this.shared_key, 0);
			//Setto la nuova chiave del cifrario
			this.getAES().setKey(this.shared_key.toByteArray());
			
			//Leggo il nounce usando la chiave condivisa e lo salvo
			byte[] _recv_IV_nounce_enc=Arrays.copyOfRange(_read, ((IV_key_length+TLV.INT_LENGTH_BYTE)), _read.length);
			byte[] IV_nounce=Arrays.copyOfRange(_recv_IV_nounce_enc, 0, IV_length);
			byte[] _recv_nounce_enc=Arrays.copyOfRange(_recv_IV_nounce_enc, IV_length, _recv_IV_nounce_enc.length);
			
			this.getAES().initDecipher(IV_nounce, true);
			byte[] _recv_nounce=this.getAES().decipherData(_recv_nounce_enc);
			this.setRb(new BigInteger(_recv_nounce));
			
			return createSendEKE3();
		}
		return false;
	}
	
	/**
	 * Questo metodo manda criptati con la chiave di sessione derivata K:
	 * -nounce di a
	 * -nounce di b
	 * @return true se l'operazione è corretta, false altrimenti
	 */
	private boolean createSendEKE3(){
	
		byte[] _ra=this.getRa().toByteArray();
		byte[] _rb=this.getRb().toByteArray();
		
		byte[] send=Service.concatArray(_rb, _ra);
		
		//inizializzo if cifrario con la chiave K e genero un IV
		this.getAES().initChiper(true);
		byte[] send_enc=this.getAES().cipherData(send);
		
		byte[] IV_nounces=Service.concatArray(this.getAES().getIV(), send_enc);
		
		TLV packet=new TLV(TLV.TAG.EKE_3,IV_nounces);
		try {
			packet.sendTLV(this.getOut());
		}
		catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		
		this.setExpected_tag(TLV.TAG.EKE_4);
		this.state=States_Client.WAIT_EKE4;
		
		return true;
	}
	
	/**
	 * Processa il nounce di b e verifica che sia corretto
	 * @return
	 * @throws IOException 
	 */
	private boolean processEKE4() throws IOException 
	{
		byte[] _read=TLV.getV(this.getIn());
				
		byte[] IV_ra=Arrays.copyOfRange(_read, 0, this.getAES().getIV().length);
		
		byte[] _ra_enc=Arrays.copyOfRange(_read, this.getAES().getIV().length,_read.length);
		
		//inizializzo il decifratore con l'IV e decifro
		this.getAES().initDecipher(IV_ra, true);
		byte[] _ra=this.getAES().decipherData(_ra_enc);
		
		BigInteger _Ra=new BigInteger(_ra);
		
		if(this.Ra.compareTo(_Ra)==0){
			Service.log("Verifica del nounce Ra corretta.", 0);
		}
		return false;
	}
	
	public String getState(){
		 return this.state.toString();
	}
	public TLV.TAG getExpected_tag() {
		return expected_tag;
	}
	public void setExpected_tag(TLV.TAG expected_tag) {
		this.expected_tag = expected_tag;
	}
	public AsymmetricCipherKeyPair getDH_key() {
		return DH_key;
	}
	public void setDH_key(AsymmetricCipherKeyPair dH_key) {
		DH_key = dH_key;
	}
	public BigInteger getRb() {
		return Rb;
	}
	public void setRb(BigInteger rb) {
		Rb = rb;
	}
	public BigInteger getRa() {
		return Ra;
	}
	public void setRa(BigInteger ra) {
		Ra = ra;
	}
}
