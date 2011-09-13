import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class FSM_Client extends FSM {

	private enum States_Client{
		WAIT_DH_PARAM_CONFIRM,
		WAIT_EKE2,
		WAIT_EKE4,
		WAIT_FILE;
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
	 * La sequenza di invio � P->Q->G
	 * @return true, se l'invio � andato correttamente e si attende il prossimo passo, false se non 
	 * funziona qualcosa
	 * @throws IOException 
	 */
	public boolean start() throws IOException {

		//ESTRAGGO dalla chiave pubblica i parametri per il generatore di chiavi DH e li invio
		DHPublicKeyParameters public_param=(DHPublicKeyParameters) DH_key.getPublic();
		BigInteger p=public_param.getParameters().getP();
		BigInteger g=public_param.getParameters().getG();

		TLV p_tlv=new TLV(TLV.TAG.DH_P,p.toByteArray());
		TLV g_tlv=new TLV(TLV.TAG.DH_G,g.toByteArray());

		p_tlv.sendTLV(getOut());
		g_tlv.sendTLV(getOut()); 


		this.state=States_Client.WAIT_DH_PARAM_CONFIRM;
		this.setExpected_tag(TLV.TAG.DH_PARAM_CONFIRM);
		return true;
	}


	public boolean nextStep() throws IOException, InvalidCipherTextException, IncorrectNounceException, IncorrectHostnameException, ResetMachineException, IncorrectTagException {

		int recv_tag=TLV.getT(this.getIn());
		//Prelevo il tag del pacchetto inviato, e controllo se
		//� il pacchetto che mi aspetto
		if (recv_tag==this.expected_tag.getCode())
		{
			//Implemento la logica di gestione in base allo stato in cui mi trovo
			switch(this.state){
			case WAIT_DH_PARAM_CONFIRM:
				this.getIn().readInt();//tolgo il campo L che altrimenti falserebbe la lettura
				return createSendEKE1();
			case WAIT_EKE2:
				return processEKE2();
			case WAIT_EKE4:
				return processEKE4();
			case WAIT_FILE:
				return processFileClose();
			}
		}
		else if (recv_tag==TLV.TAG.RESET.getCode()){
			Service.log("Ricevuto messaggio di reset. Per sicurezza tutti i parametri saranno rigenerati", 0);
			this.getIn().readInt();
			throw new ResetMachineException();
		}
		else if (recv_tag==TLV.TAG.ABORT.getCode()){
			Service.log("La macchina remota ha deciso di non continuare con la sessione. Il programma termina", 0);
			this.getIn().readInt();
			System.exit(-1);
		}
		else{
			Service.log("ERRORE, tag ricevuto non  corretto", 0);
			Service.log("TAG ricevuto"+recv_tag, 0);
			throw new IncorrectTagException();
		}
		return false;
	}


	/**
	 * Genera la chiave pubblica e la invia, serializzata con il nome. La chiave pubblica viene criptata con la chiave condivisa
	 * @return true, se il passo � stato compiuto correttamente. false altrimenti
	 * @throws InvalidCipherTextException 
	 * @throws IOException 
	 */
	private boolean createSendEKE1() throws InvalidCipherTextException, IOException{

		byte[] name=Service.intToBytes(getHost_id());
		BigInteger key_public=((DHPublicKeyParameters) DH_key.getPublic()).getY();
		byte[] key_public_arr=key_public.toByteArray();
		//Service.log("Dimensione chiave condivisa: "+key_public_arr.length,0);
		Service.log("Chiave pubblica: "+ key_public.toString(16), 0);

		byte[] key_public_enc=this.getAES().cipherData(key_public_arr);

		BigInteger key_public_enc_print=new BigInteger(key_public_enc);
		Service.log("Chiave pubblica criptata: "+ key_public_enc_print.toString(16), 0);
		//Service.log("Initialization vector: "+new BigInteger(this.getAES().getIV_Chiper()).toString(16), 0);

		//creo il contenuto informativo cifrato, mando IV+chiave cifrata
		byte[] IV_key=Service.concatArray(this.getAES().getIV_Chiper(), key_public_enc);

		byte[] T=Service.concatArray(name, IV_key);

		TLV to_send=new TLV(TLV.TAG.EKE_1, T);
		Service.log("Mando EKE1", 0);
		to_send.sendTLV(this.getOut());
		this.state=States_Client.WAIT_EKE2;
		this.expected_tag=TLV.TAG.EKE_2;

		return true;
	}

	/**
	 * Controlla l'identit� dell'host B.
	 * Genera la chiave di sessione.
	 * Invia il pacchetto di conferma al server
	 * @return
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws IncorrectHostnameException 
	 */
	private boolean processEKE2() throws IOException, InvalidCipherTextException, IncorrectHostnameException{

		Service.log("Processo EKE2", 0);

		byte[] _read=TLV.getV(this.getIn());

		if (TLV.getHostId(_read)==this.getBrother_host_id()){

			//Genero il nounce
			this.setRa(Service.createNounce());

			//Calcolo le lunghezze per leggere il pacchetto
			int nounce_length=this.getAES().getOutSize(this.Ra.toByteArray());
			int IV_length=this.getAES().getIV_Chiper().length;

			int IV_key_length=_read.length-TLV.INT_LENGTH_BYTE-IV_length-nounce_length;
			//								sottraggo il nome host   sottraggo il nounce criptato 
			//ricevo la chiave condivisa
			byte[] _recv_IV_pk=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE, (IV_key_length+TLV.INT_LENGTH_BYTE));
			Service.log("Ricezione della chiave pubblica DH", 0);

			//estraggo IV e inizializzo il motore per decriptare
			byte[] IV_pubkey=Arrays.copyOfRange(_recv_IV_pk, 0, IV_length);
			this.getAES().initDecipher(IV_pubkey, true);

			//estraggo e decifro la chiave pubblica di B
			byte[] pubkey_enc=Arrays.copyOfRange(_recv_IV_pk, IV_length, _recv_IV_pk.length);
			byte[] pubkey=this.getAES().decipherData(pubkey_enc);

			//genero la chiave condivisa
			this.server_pub_key= new BigInteger(pubkey);
			Service.log("Generazione della chiave condivisa", 0);
			this.shared_key=DHUtilities.calculateDHAgreement((DHPrivateKeyParameters)this.getDH_key().getPrivate(), this.server_pub_key,(DHParameters) ((DHKeyParameters) this.getDH_key().getPublic()).getParameters());
			Service.log("Chiave condivisa: "+this.shared_key.toString(16), 0);
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
		else{
			Service.log("Nome host non corretto", 0);
			throw new IncorrectHostnameException();
		}
	}

	/**
	 * Questo metodo manda criptati con la chiave di sessione derivata K:
	 * -nounce di a
	 * -nounce di b
	 * @return true se l'operazione � corretta, false altrimenti
	 * @throws InvalidCipherTextException 
	 * @throws IOException 
	 */
	private boolean createSendEKE3() throws InvalidCipherTextException, IOException{

		
		Service.log("Nounce Ra: "+ this.getRa(), 0);
		byte[] _ra=this.getRa().toByteArray();
		byte[] _rb=this.getRb().toByteArray();

		byte[] send=Service.concatArray(_rb, _ra);

		//inizializzo if cifrario con la chiave K e genero un IV
		this.getAES().initChiper(true);
		byte[] send_enc=this.getAES().cipherData(send);

		byte[] IV_nounces=Service.concatArray(this.getAES().getIV_Chiper(), send_enc);

		TLV packet=new TLV(TLV.TAG.EKE_3,IV_nounces);
		Service.log("Mando EKE3", 0);
		packet.sendTLV(this.getOut());
		this.setExpected_tag(TLV.TAG.EKE_4);
		this.state=States_Client.WAIT_EKE4;

		return true;
	}

	/**
	 * Processa il nounce di b e verifica che sia corretto
	 * @return
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws IncorrectNounceException 
	 */
	private boolean processEKE4() throws IOException, InvalidCipherTextException, IncorrectNounceException 
	{
		Service.log("Processo EKE4", 0);
		byte[] _read=TLV.getV(this.getIn());

		byte[] IV_ra=Arrays.copyOfRange(_read, 0, this.getAES().getIV_Chiper().length);

		byte[] _ra_enc=Arrays.copyOfRange(_read, this.getAES().getIV_Chiper().length,_read.length);

		//inizializzo il decifratore con l'IV e decifro
		this.getAES().initDecipher(IV_ra, true);
		byte[] _ra=this.getAES().decipherData(_ra_enc);

		BigInteger _Ra=new BigInteger(_ra);

		if(this.Ra.compareTo(_Ra)==0){
			Service.log("Verifica del nounce Ra corretta", 0);
			return CreateSendFile();
		}
		else{
			Service.log("Nounce ricevuto non corretto", 0);
			throw new IncorrectNounceException();
		}
	}

	private boolean CreateSendFile() throws IOException, InvalidCipherTextException{

		Service.log("Desideri inviare un file?", 0);
		if(Service.siOno("")){
			boolean corretto=false;
			File file = null;
			FileInputStream fin = null;
			
			while(!corretto){
				Service.log("Inserisci il pathname del file da inviare", 0);
				String path=Service.leggiStringa("");
				file=new File(path);
				try {
					corretto=true;
					fin=new FileInputStream(file);
				} 
				catch (FileNotFoundException e) {
					Service.log("Il file non esiste, controllare il pathname", 0);
					corretto=false;
				}
			}
			
			byte[] to_send=new byte[(int) file.length()];
			fin.read(to_send);
			//inizializzo AES con un nuovo IV e cripto il file
			
			this.getAES().initChiper(true);
			byte[] to_send_enc=this.getAES().cipherData(to_send);
			byte[] IV_pack=Service.concatArray(this.getAES().getIV_Chiper(), to_send_enc);
			
			TLV packet=new TLV(TLV.TAG.FILE, IV_pack);
			packet.sendTLV(this.getOut());
			this.expected_tag=TLV.TAG.FILE;
			this.state=States_Client.WAIT_FILE;
			return true;
		}
		else{
			byte[] vuoto= new byte[0];
			TLV packet=new TLV(TLV.TAG.FILE, vuoto);
			packet.sendTLV(this.getOut());
			this.expected_tag=TLV.TAG.FILE;
			this.state=States_Client.WAIT_FILE;
			return true;
		}
	}


	private boolean processFileClose() throws IOException, InvalidCipherTextException {
		Service.log("Attesa per la ricezione file", 0);
		byte[] read=TLV.getV(this.getIn());
		if (read.length==0){
			Service.log("Nessun file ricevuto. Scambio terminato",0);
			return false;
		}
		else{
			
			boolean continua=false;
			FileOutputStream fout = null;
			
			byte[] IV=Arrays.copyOfRange(read, 0, this.getAES().getIV_Chiper().length);
			byte[] data_enc=Arrays.copyOfRange(read, this.getAES().getIV_Chiper().length, read.length);
			this.getAES().initDecipher(IV, true);
			
			while(!continua){
				Service.log("Inserire il pathname (incluso il nome del file) dove salvare il file ricevuto",0);
				String path=Service.leggiStringa("");
				try{
				     fout=new FileOutputStream(path);
				     fout.write(this.getAES().decipherData(data_enc));
					continua=true;

				}
				catch (FileNotFoundException e){
					Service.log("Pathname non corretto, riprovare", 0);
					continua=false;
				}
			}
				Service.log("File salvato",0);
				return false;
		}
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
