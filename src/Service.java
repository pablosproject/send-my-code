

import java.nio.ByteBuffer;
import java.util.*;


public  class Service
{

    static Scanner input = new Scanner(System.in);

    /*
     *Stampa un messaggio di log, aggiungendo il tempo
     */
    
	public static void log(String messaggio)
	{
		 Calendar calendario=Calendar.getInstance();
		 String orario;
		  int ore = calendario.get(Calendar.HOUR);
		  int minuti = calendario.get(Calendar.MINUTE);
		  int secondi = calendario.get(Calendar.SECOND);
		  
		  if(calendario.get(Calendar.AM_PM) == 0)
			  orario = "A.M.";
			  else
			  orario = "P.M.";
			  
		  System.out.println(ore+":"+minuti+":"+secondi+" - "+messaggio);
	}

	/**
	 * Legge una stringa e la ritorna
	 * @param msg il messaggio da scrivere
	 * @return la stringa letta
	 */
	
	public static String leggiStringa(String msg) {
	
	    String stringa = "";
	    boolean letto = false;
	
	    while (letto == false) {
	        System.out.println(msg + " ");
	        stringa = input.next();
	        stringa = stringa.trim();
	
	        if (stringa.isEmpty()) {
	            System.out.println("[ERRORE] Hai inserito un valore vuoto.");
	        } 
	        else {
	            letto = true;
	        }
	    }
	
	    return stringa;
	}

	public byte[] intToBytes( final int i ) 
	{
	    ByteBuffer bb = ByteBuffer.allocate(4); 
	    bb.putInt(i); 
	    return bb.array();
	}
}
