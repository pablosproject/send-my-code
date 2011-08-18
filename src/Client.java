
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;

public class Client extends Connection
{
	private Socket socket;

	/**
	 * Inizializza il client su localhost e porta
	 * @param port la porta da utilizzare
	 */
	public Client(int port)
	{
		boolean continua=true;
		boolean risultato = false;
		while(continua){
			 risultato=createSocket(port);
			if(risultato)
				continua=false;
			else{
				Service.log("Errore nella connessione. Controllare i parametri.",0);
				 continua=Service.siOno("Si desidera riprovare a connettersi?");
			}
		}
		
		if (risultato){

			try {
				this.setIn(new DataInputStream(this.socket.getInputStream()));
				Service.log("Client: stream output creato", 2);
			} 
			catch (IOException e) {
				Service.log("Client: errore nella creazione dello stream output", 2);
				e.printStackTrace();
			}
			try {
				this.setOut(new DataOutputStream(this.socket.getOutputStream()));
				Service.log("Client: stream input creato", 2);
			} 
			catch (IOException e) {
				Service.log("Client: errore nella creazione dello stream input", 2);
				e.printStackTrace();
			}
		}
		
		else{
			Service.log("Socket non creato a causa di errori.", 0);
		}
		
	}
	
	public boolean createSocket(int port)
	{
		try
		{
			this.socket=new Socket("localhost",port);
			Service.log("Client: socket creato e connesso al server", 2);
		} 
		catch (UnknownHostException e)
		{
			Service.log("Client: il server non esiste, oppure non risponde", 2);
			return false;
		}
		catch (ConnectException e) {
			Service.log("L'host non è raggiungibile", 0);
			return false;
		}
		catch (IOException e)
		{
			Service.log("Client: errore nella creazione del socket", 2);
			e.printStackTrace();
			return false;
		}
		
		return true;
	}
	
	
	public void send(int manda1) 
	{
		try {
			byte[] primo=Service.intToBytes(manda1);
			byte[] secondo=Service.intToBytes(manda1*2);
			
			byte[] scrivi=Service.concatArray(primo, secondo);
			this.getOut().write(scrivi);
			this.getOut().flush();
		} 
		catch (IOException e) {
			Service.log("Client: non ho potuto inviare sullo stream", 2);
			e.printStackTrace();
		}
	}



	
}
