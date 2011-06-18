
import java.io.IOException;
import java.net.*;

public class Server extends Connessione 
{

	private ServerSocket server_socket;
	private Socket client_socket;
	
	
	/*
	 * Il costruttore inizializza il server e lo mette in attesa di connessioni
	 */
	public Server(int port) throws IOException
	{
		this.server_socket=new ServerSocket(port);
	}
	
	@Override
	public void send() 
	{
		// TODO Auto-generated method stub

	}

	@Override
	public void connect() throws IOException 
	{
		Service.log("In attesa di connessioni dal Client");
		this.client_socket= server_socket.accept();
		
	}

}
