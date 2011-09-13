import java.io.IOException;

public class main 
{
	public static void main(String [] args)
	{
		
		char tipo=Service.tipoMacchina();
		Host host = null;
			if (tipo=='a')
				try {
					host = new Host(1);
				} catch (IOException e) {
					e.printStackTrace();
				}
			else if (tipo=='c')
				try {
					host=new Host(0);
				} catch (IOException e) {
					e.printStackTrace();
				}
		host.startHost();
	
	}
}
