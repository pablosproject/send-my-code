
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import java.net.*;

public class Server extends Connection {

	private ServerSocket server_socket;
	private Socket client_socket;



	/**Crea un server e fa il bind sull'indirizzo corrente
	 * @param port porta del server
	 */
	
	public Server(int port)  {
		
		try {
			this.server_socket=new ServerSocket(port);
		    Service.log(this.server_socket.getInetAddress().toString(), 2);
			
		} 
		catch (IOException e) {
			Service.log("Server: errore alla creazione del socket", 2);
			e.printStackTrace();
		}
		connect();
	}

	
	/**
	 * Inizializza il client socket, attendendo la richiesta dal client e creando l'input e l'output stream
	 */
	public void connect(){
		
		Service.log("Server: In attesa di connessioni dal Client", 2);
		try {
			this.client_socket = server_socket.accept();
		} 
		catch (IOException e) {
			Service.log("Server: errore nella creazione del socket Client", 2);
			e.printStackTrace();
		}
		if (this.client_socket != null){
			try {
				this.server_socket.close();
			} 
			catch (IOException e) {
				Service.log("Errore nella chiusura del socket Server", 2);
				e.printStackTrace();
			}
		}
	
		Service.log("Server: connessione avvenuta con successo", 2);
		//Estraggo gli input e out stream su cui scrivere.
		
		try {
			this.setOut(new DataOutputStream(client_socket.getOutputStream()));
		} 
		catch (IOException e) {
			Service.log("Server: Errore nella creazione dell'output stream", 2);
			e.printStackTrace();
		}
		
		try {
			this.setIn(new DataInputStream(client_socket.getInputStream()));
		} 
		catch (IOException e) {
			Service.log("Server: Errore nella creazione dell'input stream", 2);
			e.printStackTrace();
		}
	
	}


	/**
	 * Chiude il socket del server
	 */
	public void close()
	{
		if (!this.server_socket.isClosed())
		{
			try {
				this.server_socket.close();
			} 
			catch (IOException e) {
				Service.log("Errore nella chiusura del socket Server", 2);
				e.printStackTrace();
			}
		}
	}
}
