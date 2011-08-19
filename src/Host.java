import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;


public class Host
{
	private Connection connection;
	private FSM fsm;
	private AsymmetricCipherKeyPair key;
	private int host_id;
	private int brother_host_id;
	
	public Host(int type_connection, int port,int _host_id, int _brother_host_id, String chiave) throws IOException
	{
		if (type_connection==0){
			this.connection=new Client(port,"192.168.0.8");
			createDHParameters();
			this.setFsm(new FSM_Client(connection.getOut(), connection.getIn(), this.key, _host_id, _brother_host_id,chiave));
			this.setBrother_host_id(_brother_host_id);
			this.setHost_id(_host_id);
			
		}
		else if (type_connection==1){
			this.connection=new Server(port);
			this.setFsm(new FSM_Server(connection.getOut(),connection.getIn(), _host_id, _brother_host_id,chiave));
			this.setBrother_host_id(_brother_host_id);
			this.setHost_id(_host_id);
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
		boolean continua=this.fsm.start();
		
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
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
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
