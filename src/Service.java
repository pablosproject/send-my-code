

import java.util.*;


public  class Service
{

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
}
