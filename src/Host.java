import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;


public class Host
{
	private Connection connection;
	private FSM fsm;
	
	public Host(int type_connection) throws IOException
	{
		if (type_connection==0){
			this.setFsm(new FSM_Client(connection.getOut(), connection.getIn(), null));
		}
		else if (type_connection==1){
			this.setFsm(new FSM_Server(connection.getOut(),connection.getIn()));
		}
		else
			Service.log("Errore, tipo di connessione sconosciuto", 2);
	}

	public void createDHParameters()
	{
//		DHParametersGenerator parameter_gen= new DHParametersGenerator();
//		parameter_gen.init(1024, 80, new SecureRandom());
//		DHParameters parameter=parameter_gen.generateParameters();
		
		
	}

	public FSM getFsm() {
		return fsm;
	}

	public void setFsm(FSM fsm) {
		this.fsm = fsm;
	}
}
