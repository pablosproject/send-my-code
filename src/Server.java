
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

		int port_connect=port;
		boolean riuscito=false;
		
		while(!riuscito){
			boolean riuscito_socket;
			try {
				this.server_socket=new ServerSocket(port_connect);
				riuscito_socket=true;
			} 
			catch(IllegalArgumentException e){
				Service.log("Porta fuori range",1);
//				e.printStackTrace();
				riuscito_socket=false;
			}
			catch (BindException e){
				Service.log("Non risulta possibile fare il bind sulla porta "+port_connect+". Porta bloccata.",1);
				riuscito_socket=false;
			}
			catch (IOException e) {
				Service.log("Errore alla creazione del socket", 1);
//				e.printStackTrace();
				riuscito_socket=false;
			}
			
			boolean riuscito_connect=false;
			
			if(!riuscito_socket){
				Service.log("Ci sono problemi a creare il socket.", 1);
				if(Service.siOno("Vuoi cambiare il numero di porta?")){
					port_connect=Service.leggiIntero("Immetti il numero di porta", true);
				}
			}
			else
				riuscito_connect=connect();
			
			riuscito=riuscito_socket&&riuscito_connect;

		}
	}


	/**
	 * Inizializza il client socket, attendendo la richiesta dal client e creando l'input e l'output stream
	 */
	public boolean connect(){

		Service.log("Server: In attesa di connessioni dal Client", 2);
		try {
			this.client_socket = server_socket.accept();
		} 
		catch (IOException e) {
			Service.log("Server: errore nella creazione del socket Client", 2);
			e.printStackTrace();
			return false;
		}
		if (this.client_socket != null){
			try {
				this.server_socket.close();
			} 
			catch (IOException e) {
				Service.log("Errore nella chiusura del socket Server", 2);
				e.printStackTrace();
				return false;
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
			return false;
		}

		try {
			this.setIn(new DataInputStream(client_socket.getInputStream()));
		} 
		catch (IOException e) {
			Service.log("Server: Errore nella creazione dell'input stream", 2);
			e.printStackTrace();
			return false;
		}

		return true;

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
