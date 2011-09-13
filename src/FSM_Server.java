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
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class FSM_Server extends FSM {

	private enum States_Server{
		WAIT_EKE1,
		WAIT_EKE3,
		WAIT_FILE;
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
			int codice_P=TLV.getT(this.getIn());
			if (codice_P==TLV.TAG.DH_P.getCode()){
				byte[] letto_p=TLV.getV(getIn());
				p=new BigInteger(letto_p);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perch� gli altri tag non li leggo
			}


			int codice_G=TLV.getT(getIn());
			if (codice_G==TLV.TAG.DH_G.getCode()){
				byte[] letto_g=TLV.getV(getIn());
				g=new BigInteger(letto_g);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perch� gli altri tag non li leggo
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

	public boolean nextStep() throws IOException, InvalidCipherTextException, IncorrectHostnameException, IncorrectNounceException, ResetMachineException, IncorrectTagException {

		int recv_tag=TLV.getT(this.getIn());
		//Prelevo il tag del pacchetto inviato, e controllo se
		//� il pacchetto che mi aspetto
		if (recv_tag==this.expected_tag.getCode())
		{
			//Implemento la logica di gestione in base allo stato in cui mi trovo
			switch(this.state){
			case WAIT_EKE1:
				return processEKE1();
			case WAIT_EKE3:
				return processEKE3();	
			case WAIT_FILE:
				return processFileSendClose();
			}
		}
		else if (recv_tag==TLV.TAG.RESET.getCode()){
			Service.log("Ricevuto messaggio di reset. Per sicurezza tutti i parametri saranno rigenerati", 1);
			this.getIn().readInt();
			throw new ResetMachineException();
		}
		else if (recv_tag==TLV.TAG.ABORT.getCode()){
			Service.log("L'altra macchina ha deciso di non continuare con la sessione. Il programma termina", 1);
			this.getIn().readInt();
			System.exit(-1);
		}
		else{
			Service.log("ERRORE, tag ricevuto non  corretto: "+recv_tag, 1);
			throw new IncorrectTagException();
		}
		
		return false;
	}



	/**
	 * Controlla che l'utente che richiede autenticazione sia quello corretto. 
	 * Genera la chiave condivisa
	 * Genera il pacchetto di risposta EKE2 e lo invia al client
	 * @return
	 * @throws IOException eccezoni generate dall'invio e ricezione sul socket
	 * @throws InvalidCipherTextException Eccezione generata in quanto la chiave non � corretta o il ciphertext � corrotto
	 * @throws IncorrectHostnameException 
	 */
	private boolean processEKE1() throws IOException, InvalidCipherTextException, IncorrectHostnameException{

		Service.log("Processo EKE1", 1);
		//ho già controllato che il pacchetto sia di tipo EKE1
		//ora controllo che il nome della persona corrisponda a colui di cui posseggo la chiave
		byte[] _read=TLV.getV(this.getIn());

		if (TLV.getHostId(_read)==this.getBrother_host_id())
		{
			int _IV_length=this.getAES().getIV_Chiper().length;
			//prelevo l'IV dall'inizio del cifrato
			byte [] _IV_recv=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE, TLV.INT_LENGTH_BYTE+_IV_length);
			//passo di generazione della chiave condivisa
			byte[] _recv_k_enc=Arrays.copyOfRange(_read, TLV.INT_LENGTH_BYTE+_IV_length, _read.length) ;
			Service.log("Ricezione della chiave pubblica DH", 1);

			//decripto la chiave pubblica ottenuta dal client
			this.getAES().initDecipher(_IV_recv, true);
			byte[] _recv_k=this.getAES().decipherData(_recv_k_enc);

			this.client_pub_key= new BigInteger(_recv_k);
			Service.log("Generazione della chiave condivisa", 1);
			this.shared_key=DHUtilities.calculateDHAgreement((DHPrivateKeyParameters)key.getPrivate(), this.client_pub_key,this.getParameter());
			Service.log("Chiave condivisa: "+this.shared_key.toString(16), 1);

			//invio della propria chiave pubblica
			return createSendEKE2();
		}
		else{ 
			Service.log("Nome host ricevuto non corretto",1);
			throw new IncorrectHostnameException();
		}
	}

	/**
	 * 
	 * @return true se l'invio � corretto, false invece
	 * @throws InvalidCipherTextException Errore se la chiave non � corretta
	 * @throws IOException 
	 */
	private boolean createSendEKE2() throws InvalidCipherTextException, IOException
	{
		//ottengo il nome dell'host da mandare
		byte[] name=Service.intToBytes(this.getHost_id());

		BigInteger key_public=((DHPublicKeyParameters) this.getKey().getPublic()).getY();
		byte[] key_public_arr=key_public.toByteArray();
		//Service.log("Dimensione chiave pubblica:"+key_public_arr.length, 1);

		Service.log("Chiave pubblica: "+ key_public.toString(16), 1);

		byte[] key_public_enc=this.getAES().cipherData(key_public_arr);

		BigInteger key_public_enc_print=new BigInteger(key_public_enc);

		Service.log("Chiave pubblica criptata: "+ key_public_enc_print.toString(16), 1);
		//Service.log("Initialization vector: "+new BigInteger(this.getAES().getIV_Chiper()), 1);

		byte[] IV_key=Service.concatArray(this.getAES().getIV_Chiper(), key_public_enc);
		byte[] name_key=Service.concatArray(name, IV_key);

		//creo il nuounce di B e lo mando ad A criptato
		this.Rb=Service.createNounce();
		Service.log("Nounce B: "+this.Rb,1);

		byte[] nounce=Rb.toByteArray();

		//cambio la chiave al motore AES e lo reinizializzo con un nuovo IV
		this.getAES().setKey(this.shared_key.toByteArray());
		this.getAES().initChiper(true);

		//Service.log("Cambio di chiave avvenuto: "+ Arrays.equals(this.getAES().getKey(),this.shared_key.toByteArray()), 1);

		byte[] nounce_enc=this.getAES().cipherData(nounce);
		//Service.log("Dimensione del nounce prima: "+nounce.length+" dimensione del nounce criptato: "+nounce_enc.length, 1);
		byte[] IV_rb=this.getAES().getIV_Chiper();

		byte[] IV_nounce=Service.concatArray(IV_rb, nounce_enc);

		byte[] V=Service.concatArray(name_key, IV_nounce);

		TLV to_send=new TLV(TLV.TAG.EKE_2, V);
		Service.log("Mando EKE2", 1);
		to_send.sendTLV(this.getOut());
		this.setState(States_Server.WAIT_EKE3);
		this.setExpected_tag(TLV.TAG.EKE_3);
		return true;
	}

	private boolean processEKE3() throws IOException, InvalidCipherTextException, IncorrectNounceException{
		
		Service.log("Processo EKE3", 1);
		byte[] _read=TLV.getV(this.getIn());

		int length_rb=this.getRb().toByteArray().length;

		byte[] IV_rb_ra=Arrays.copyOfRange(_read, 0, this.getAES().getIV_Chiper().length);

		byte[] _rb_ra_enc=Arrays.copyOfRange(_read, this.getAES().getIV_Chiper().length,_read.length);

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
		else{
			Service.log("Nounce non verificato.", 1);
			throw new IncorrectNounceException();
		}

	}

	/**
	 * Cripta il nounce ricevuto da A con la chiave generata, ni modo da confermare
	 * @return
	 * @throws InvalidCipherTextException 
	 * @throws IOException 
	 */
	private boolean createSendEKE4() throws InvalidCipherTextException, IOException {

		byte[] _ra=this.getRa().toByteArray();

		//inizializzo il cifrario con la chiave K e genero un nuovo IV
		this.getAES().initChiper(true);
		byte[] send_enc=this.getAES().cipherData(_ra);

		byte[] IV_nounces=Service.concatArray(this.getAES().getIV_Chiper(), send_enc);

		TLV packet=new TLV(TLV.TAG.EKE_4,IV_nounces);
		Service.log("Mando EKE 4", 1);
		packet.sendTLV(this.getOut());
		this.setExpected_tag(TLV.TAG.FILE);
		this.state=States_Server.WAIT_FILE;
		return true;

	}
	
	
	private boolean processFileSendClose() throws IOException, InvalidCipherTextException {
		
		Service.log("Attesa per la ricezione file", 1);
		byte[] read=TLV.getV(this.getIn());
		if (read.length==0){
			Service.log("Nessun ile ricevuto. Scambio terminato",0);
		}
		else{
			
			boolean continua=false;
			FileOutputStream fout = null;
			
			byte[] IV=Arrays.copyOfRange(read, 0, this.getAES().getIV_Chiper().length);
			byte[] data_enc=Arrays.copyOfRange(read, this.getAES().getIV_Chiper().length, read.length);
			this.getAES().initDecipher(IV, true);
			
			while(!continua){
				Service.log("Inserire il pathname (incluso il nome del file) dove salvare il file ricevuto",1);
				String path=Service.leggiStringa("");
				try{
					continua=true;
				     fout=new FileOutputStream(path);
				     fout.write(this.getAES().decipherData(data_enc));
				}
				catch (FileNotFoundException e){
					Service.log("Pathname non corretto, riprovare", 1);
					continua=false;
				}
			}
				Service.log("File salvato",1);
		}
		return sendFile();
	}

	
	private boolean sendFile() throws IOException, InvalidCipherTextException {

		Service.log("Desideri inviare un file?", 1);
		if(Service.siOno("")){
			boolean corretto=false;
			File file = null;
			FileInputStream fin = null;
			
			while(!corretto){
				Service.log("Inserisci il pathname del file da inviare", 1);
				String path=Service.leggiStringa("");
				file=new File(path);
				try {
					corretto=true;
					fin=new FileInputStream(file);
				} 
				catch (FileNotFoundException e) {
					Service.log("Il file non esiste, controllare il pathname", 1);
					corretto=false;
				}
			}
			
			byte[] to_send=new byte[(int) file.length()];
			fin.read(to_send);
			
			this.getAES().initChiper(true);
			byte[] to_send_enc=this.getAES().cipherData(to_send);
			byte[] IV_pack=Service.concatArray(this.getAES().getIV_Chiper(), to_send_enc);
			
			TLV packet=new TLV(TLV.TAG.FILE, IV_pack);
			packet.sendTLV(this.getOut());
			return false;
		}
		else{
			byte[] vuoto= new byte[0];
			TLV packet=new TLV(TLV.TAG.FILE, vuoto);
			packet.sendTLV(this.getOut());
			return false;
		}
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
