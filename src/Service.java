

import java.math.BigInteger;
import java.security.SecureRandom;
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
		 @SuppressWarnings("unused")
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
			  host="Client";
		  else if (c_s==1)
			  host="Server";
		  
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
		return c;
	}
	
	public static boolean siOno(String messaggio) {
	    while (true) {
	        char c = leggiChar(messaggio + " [S/N]\n");
	        if (c == "S".toCharArray()[0] || c == "s".toCharArray()[0]) {
	            return true;
	        } else if (c == "N".toCharArray()[0] || c == "n".toCharArray()[0]) {
	            return false;
	        } else {
	            System.out.println("[ERRORE] Devi inserire S o N.");
	        }
	    }
	}
	
	public static char leggiChar(String msg) {
		
	    char carattere;
	    boolean letto = false;
	
	    while (letto == false) {
	        System.out.print(msg);
	        String stringa = input.next();
	
	        stringa = stringa.trim();
	        if (stringa == "") {
	            System.out.print("[ERRORE] Hai inserito un valore vuoto.");
	        } else if (stringa.length() > 1) {
	            System.out.print("[ERRORE] Devi inserire solo un carattere.");
	        } else {
	            char[] caratteri = new char[1];
	            caratteri = stringa.toCharArray();
	            carattere = caratteri[0];
	            letto = true;
	            return carattere;
	        }
	    }
	    return 'a';
	}
	
	public static BigInteger createNounce(){
		
		//forzo a cercare un biginteger che rappresentao in byte sia di 32 byte
		boolean trovato=false;
		BigInteger nounce = null;
		while(!trovato){
			SecureRandom random_gen= new SecureRandom();
			nounce=new BigInteger(256, random_gen);
			if(nounce.toByteArray().length==32){
				trovato=true;
			}
		}
		return nounce;
	}

}



