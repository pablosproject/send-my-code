import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;


public class Host
{
	private Connection connection;
	private FSM fsm;
	private AsymmetricCipherKeyPair key;
	private int host_id;
	private int brother_host_id;

	public Host(int type_connection) throws IOException
	{
		String chiave=Service.leggiStringa("Inserire la propria chiave personale:");
		
		//inizilizzo l'host con una macchina client
		if (type_connection==0){
			Service.log("Inserire indirizzo ip a cui connettersi:", 0);
			String ip=Service.leggiStringa("");

			Service.log("Inserire la porta su cui la macchina remota è in ascolto:", 0);
			int port=Service.leggiIntero("", true);

			this.connection=new Client(port,ip);
			this.createDHParameters();

			this.getUserParameter(0);

			this.setFsm(new FSM_Client(connection.getOut(), connection.getIn(), this.key, this.host_id, this.brother_host_id,chiave));


		}
		//inizializzo l'host con una macchina server
		else if (type_connection==1){

			Service.log("Inserire la porta su cui attendere connessioni: ", 1);
			int port=Service.leggiIntero("", true);
			this.connection=new Server(port);

			this.getUserParameter(1);

			this.setFsm(new FSM_Server(connection.getOut(),connection.getIn(), this.host_id, this.brother_host_id,chiave));

		}
		else
			Service.log("Errore creazione host, tipo di connessione sconosciuto", 2);
	}

	/**
	 * Crea una coppia di chiavi DH per l'host
	 */
	public void createDHParameters()
	{
		this.setKey(DHUtilities.GenerateClientDHKey(256, 100));
	}

	public void startHost()
	{
		boolean continua = false;
		try {
			continua = this.fsm.start();
		} catch (IOException e1) {
			Service.log("Errore di IO. Il programma termina.",2);
			e1.printStackTrace();
			System.exit(-1);
		}

		//Creo la coppia di chiavi sul server
		if (continua)
		{
			// se sono un server creo le mie chiavi prelevandole da quelle che ci sono nella macchina a stati
			if (this.fsm.getClass()==FSM_Server.class){
				FSM_Server server=(FSM_Server) this.getFsm();
				this.key=DHUtilities.GenerateServerDHKey(server.getParameter());
				server.setKey(this.key);
			}
		}
		while (continua){
			try {
				continua=this.fsm.nextStep();
			} 
			catch (IOException e) {
				Service.log("Errore di IO. Il programma termina.",2);
				e.printStackTrace();
				System.exit(-1);
			} 
			catch (InvalidCipherTextException e) {
				Service.log("ATTENZIONE. Non sono stati decifrati i messaggi arrivati in quanto " +
						"la chiave utilizzata non è corretta. La macchina viene riavviata, si consiglia di terminare l'esecuzione se questo problema si " +
						"presenta altre volte.\n Potrebbe essere il tentativo di qualche malintenzionato che conosce il nome macchina di indovinare la chiave", 2);
				this.resetMachineAndSignal();
			} 
			catch (IncorrectHostnameException e) {
				this.resetMachineAndSignal();
			} 
			catch (IncorrectNounceException e) {
				this.resetMachineAndSignal();
			} 
			catch (ResetMachineException e) {
				this.resetMachine();
			} 
			catch (IncorrectTagException e) {
				Service.log("E' stato ricevut un tag non corretto. Significa che la macchine non sono sincronizzate.", 2);
				e.printStackTrace();
				this.resetMachineAndSignal();
			}
		}
		
		Service.log("Il programa termina.", 2);
		System.exit(0);
	}

	private void resetMachineAndSignal(){
		this.fsm.sendReset();
		this.resetMachine();
	}

	private void resetMachine(){
		if(Service.siOno("A causa di problemi tutti i parametri saranno rigenerati e le macchine risettate." +
		"Si desidera continuare? (Se non si continua il processo sarà chiuso)")){
			if (this.fsm.getClass()==FSM_Client.class){
				String chiave=Service.leggiStringa("Reset Macchina.Inserire la propria chiave personale:");
				this.getUserParameter(0);
				this.createDHParameters();
				this.setFsm(new FSM_Client(connection.getOut(), connection.getIn(), this.key, this.host_id, this.brother_host_id,chiave));
			}
			else{
				String chiave=Service.leggiStringa("Reset Macchina.Inserire la propria chiave personale:");
				this.getUserParameter(1);
				this.setFsm(new FSM_Server(connection.getOut(),connection.getIn(), this.host_id, this.brother_host_id,chiave));
			}
			this.startHost();
		}
		else{
			TLV abort=new TLV(TLV.TAG.ABORT,new byte[0]);
			try {
				abort.sendTLV(this.fsm.getOut());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.exit(-2);
		}
		
		
	}

	private void getUserParameter(int type){

		Service.log("Inserire il proprio identificativo:", type);
		int	_host_id=Service.leggiIntero("", true);

		Service.log("Inserire identificativo della macchina con cui si vogliono scambiare file:", type);
		int	_brother_host_id=Service.leggiIntero("", true);

		this.setBrother_host_id(_brother_host_id);
		this.setHost_id(_host_id);
	}


	public FSM getFsm() {
		return fsm;
	}

	public void setFsm(FSM fsm) {
		this.fsm = fsm;
	}

	public AsymmetricCipherKeyPair getKey() {
		return key;
	}

	public void setKey(AsymmetricCipherKeyPair key) {
		this.key = key;
	}

	public int getHost_id() {
		return host_id;
	}

	public void setHost_id(int host_id) {
		this.host_id = host_id;
	}

	public int getBrother_host_id() {
		return brother_host_id;
	}

	public void setBrother_host_id(int brother_host_id) {
		this.brother_host_id = brother_host_id;
	}
}
