
import java.io.IOException;
import java.net.*;

public class Server extends Connessione 
{

	private ServerSocket server_socket;
	private Socket client_socket;
	
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
		this.client_socket= server_socket.accept();
		System.out.println("In attesa di connessioni dal Client");
		
	}

}
