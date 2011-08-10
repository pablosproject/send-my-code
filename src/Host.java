import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;


public class Host
{
	private Connessione connection;
	//inserisci la macchina a stati che regola il funzionamento
	
	public Host(int type_connection) throws IOException
	{
		if (type_connection==1) connection=new Client();
		else connection=new Server(2334);
	}

	public void createDHParameters()
	{
		DHParametersGenerator parameter_gen= new DHParametersGenerator();
		parameter_gen.init(1024, 80, new SecureRandom());
		DHParameters parameter=parameter_gen.generateParameters();
		
		
	}
}
