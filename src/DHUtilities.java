import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;


public class DHUtilities 
{
	/**
	 * Genera la coppia di chiavi DH.
	 * @param key_bitsize la dimensione in bit del numero primo p
	 * @return la coppia di chiavi DH
	 */
	public static AsymmetricCipherKeyPair GenerateClientDHKey(int key_bitsize,int certainity)
	{
		
		Service.log("Creazione dei parametri DH",0);
		Service.log("Creazione del generatore parametri DH",0);
		DHParametersGenerator generator= new DHParametersGenerator();
		generator.init(key_bitsize, certainity, new SecureRandom());
		Service.log("Generazione dei parametri. L'operazione potrebbe richiedere tempo" +
				"a seconda dei valori scelti per la certainity.",0);
		DHParameters parameter= generator.generateParameters();
		
		DHKeyGenerationParameters key_gen_par= new DHKeyGenerationParameters(new SecureRandom(), parameter);
		
		DHBasicKeyPairGenerator key_gen= new DHBasicKeyPairGenerator();
		key_gen.init(key_gen_par);
		
		AsymmetricCipherKeyPair key= key_gen.generateKeyPair();
		return key;
		
	}
}
