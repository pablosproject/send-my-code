import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class DHUtilities 
{
	/**
	 * Genera la coppia di chiavi DH.
	 * @param key_bitsize la dimensione in bit del numero primo p
	 * @return la coppia di chiavi DH
	 */
	public static AsymmetricCipherKeyPair GenerateClientDHKey(int key_bitsize,int certainity)
	{
		
		Service.log("Creazione del generatore parametri DH",0);
		DHParametersGenerator generator= new DHParametersGenerator();
		generator.init(key_bitsize, certainity, new SecureRandom());
		Service.log("Generazione dei parametri DH. L'operazione potrebbe richiedere tempo " +
				"a seconda dei valori scelti per il test dei numeri primi.",0);
		DHParameters parameter= generator.generateParameters();
		
		DHKeyGenerationParameters key_gen_par= new DHKeyGenerationParameters(new SecureRandom(), parameter);
		
		DHBasicKeyPairGenerator key_gen= new DHBasicKeyPairGenerator();
		key_gen.init(key_gen_par);
		
		AsymmetricCipherKeyPair key= key_gen.generateKeyPair();
		return key;
		
	}
	
	public static AsymmetricCipherKeyPair GenerateServerDHKey(DHParameters parameter){
		
		Service.log("Creo un generatore di chiavi DH con i parametri ricevuti.",1);
		DHKeyGenerationParameters key_gen_par= new DHKeyGenerationParameters(new SecureRandom(), parameter);
		
		DHBasicKeyPairGenerator key_gen= new DHBasicKeyPairGenerator();
		key_gen.init(key_gen_par);
		
		AsymmetricCipherKeyPair key=key_gen.generateKeyPair();
		return key;
	}
	
	public static BigInteger calculateDHAgreement(DHPrivateKeyParameters key_private, BigInteger key_public_int, DHParameters key_public){
	
		DHBasicAgreement agreement_generator=new DHBasicAgreement();
		agreement_generator.init(key_private);
		DHPublicKeyParameters key_param= new DHPublicKeyParameters(key_public_int,key_public );
		
		BigInteger key= agreement_generator.calculateAgreement(key_param);
		return key;
	}
	
	public static int getDHKeyLength(AsymmetricCipherKeyPair key){
	
		DHPublicKeyParameters pub=(DHPublicKeyParameters) key.getPublic();
		BigInteger pub_key=pub.getY();
		byte[] key_byte=pub_key.toByteArray();
		return key_byte.length;
		
	}
}
