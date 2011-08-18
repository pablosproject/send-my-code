import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class main 
{
	public static void main(String[] args) throws InterruptedException 
	{
		
//		Service.log("Creazione dei parametri DH 1",2);
//		DHParametersGenerator generator1= new DHParametersGenerator();
//		generator1.init(512, 100, new SecureRandom());
//		DHParameters parameter1= generator1.generateParameters();
//		
//		DHKeyGenerationParameters key_gen_par1= new DHKeyGenerationParameters(new SecureRandom(), parameter1);
//		
//		DHBasicKeyPairGenerator key_gen1= new DHBasicKeyPairGenerator();
//		key_gen1.init(key_gen_par1);
//		
//		AsymmetricCipherKeyPair key1= key_gen1.generateKeyPair();
//		DHPublicKeyParameters parametri_pub=(DHPublicKeyParameters) key1.getPublic();
//		System.out.println(parametri_pub.getParameters().toString());
//		
//		BigInteger p=parametri_pub.getParameters().getP();
////		BigInteger q=parametri_pub.getParameters().getQ();
//		BigInteger g=parametri_pub.getParameters().getG();
//		
//		Service.log("Creazione dei parametri DH 2",2);
//		
//		DHParameters parameter2= new DHParameters(p,g);
//		
//		DHKeyGenerationParameters key_gen_par2=  new DHKeyGenerationParameters(new SecureRandom(), parameter2);
//		
//		DHBasicKeyPairGenerator key_gen2=new DHBasicKeyPairGenerator();
//		key_gen2.init(key_gen_par2);
//		
//				
//		AsymmetricCipherKeyPair key2= key_gen1.generateKeyPair();
//
//
//		
//		DHBasicAgreement agreement1=new DHBasicAgreement();
//	    DHBasicAgreement agreement2=new DHBasicAgreement();
//	    
//	    agreement1.init((DHPrivateKeyParameters)key1.getPrivate());
//	    agreement2.init((DHPrivateKeyParameters)key2.getPrivate());
//	    
//	    BigInteger esito1=agreement1.calculateAgreement((DHPublicKeyParameters)key2.getPublic());
//	    BigInteger esito2=agreement2.calculateAgreement((DHPublicKeyParameters)key1.getPublic());
//	    
//	     System.out.println(esito1.equals(esito2));
//	     System.out.println(esito1);
//	     System.out.println(esito2);
//	     Integer numero=23231444;
	     
//	     System.out.println(BitConverter(10));
//	     System.out.println(esito1.toByteArray());


		

		
		Thread client= new Thread(){
		public void run()
		{
			Host client_host = null;
			try {
				client_host=new Host(0, 1235,2,1,"primo");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			client_host.startHost();
		}
		};
		
		Thread server= new Thread(){
		public void run()
		{
			Host server_host = null;
			try {
				server_host=new Host(1, 1235,1,2,"primo");
				server_host.startHost();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			server_host.startHost();
		}

		};


		client.start();

		server.start();
	
	}
}
