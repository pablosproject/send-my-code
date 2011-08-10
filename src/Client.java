
import java.io.IOException;
import java.net.*;

public class Client extends Connessione 
{
	private Socket socket;
	
	public Client()
	{
		try
		{
			this.socket=new Socket("localhost",4444);
		} 
		catch (UnknownHostException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
	
	
	@Override
	public void send() 
	{
		
		// TODO Auto-generated method stub

	}

	@Override
	public void connect() 
	{
		// TODO Auto-generated method stub

	}

	
}
