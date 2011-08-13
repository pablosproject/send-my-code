

import java.nio.ByteBuffer;
import java.util.*;


public  class Service
{

    final static String ERRORE_FORMATO = "Attenzione: il dato inserito non e' nel formato corretto";

    static Scanner input = new Scanner(System.in);

    /*
     *Stampa un messaggio di log, aggiungendo il tempo
     */
    
	public static void log(String messaggio, int c_s)
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
		
		  String host="";
		  if (c_s==0)
			  host="client";
		  else if (c_s==1)
			  host="server";
		  
		  System.out.println(ore+":"+minuti+":"+secondi+" - "+" "+host+": "+messaggio);
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

	public static byte[] intToBytes( int a) 
	{
		 byte[] ret = new byte[4];
		 ret[3] = (byte) (a & 0xFF);   
		 ret[2] = (byte) ((a >> 8) & 0xFF);   
		 ret[1] = (byte) ((a >> 16) & 0xFF);   
		 ret[0] = (byte) ((a >> 24) & 0xFF);
		return ret;
	}
	
	public static int byteToInt(byte[] b){
		
	    int value = 0;
	    for (int i = 0; i < 4; i++) {
	        value = (value << 8) | (b[i] & 0xFF);
	    }
	    return value;
		
	}

	/**
	 * Legge un numero intero dopo aver stampato un messaggio di testo
	 * @param messaggio il messaggio di testo
	 * @param aCapo per andare o meno a capo dopo il testo
	 * @return il numero intero letto da tastiera
	 */
	
	
	public static int leggiIntero(String messaggio, boolean aCapo) {
	    boolean finito = false;
	    int valoreLetto = 0;
	    do {
	        if (aCapo) {
	            System.out.println(messaggio);
	        } else {
	            System.out.print(messaggio);
	        }
	        if (input.hasNextInt()) {
	            valoreLetto =input.nextInt();
	            finito = true;
	        } else {
	            System.out.println(ERRORE_FORMATO);
	        }
	    } while (!finito);
	    return valoreLetto;
	}
	
	public static byte[] concatArray(byte[] a, byte[] b){
		
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		Service.log("Lunghezza concatenato: "+c.length, 2);
		return c;
	}
}



