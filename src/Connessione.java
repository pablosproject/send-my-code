import java.io.IOException;

/*
 * Classe che implementa la logica generica relativa a client e server
 *
 */


public abstract class  Connessione  
{
	public abstract void send();
	public abstract void connect() throws IOException;
}
