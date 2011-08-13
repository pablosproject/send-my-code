import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;


public class FSM_Client extends FSM {

	private enum States_Client{
		WAIT_DH_PARAM_CONFIRM,
		WAIT_EKE2,
		WAIT_EKE4
	}
	
	private States_Client state;
	private TLV.TAG expected_tag;
	private AsymmetricCipherKeyPair DH_key;
	
	public FSM_Client(DataOutputStream _out, DataInputStream _in, AsymmetricCipherKeyPair _key){
		
		super(_in, _out);
		this.DH_key=_key;
	}
	/**
	 * Metodo che inizia il protocollo. Invia i parametri DH pubblici all'altro host.
	 * La sequenza di invio è P->Q->G
	 * @return true, se l'invio è andato correttamente e si attende il prossimo passo, false se non 
	 * funziona qualcosa
	 */
	public boolean start() {
		
		//ESTRAGGO dalla chiave pubblica i parametri per il generatore di chiavi DH e li invio
		DHPublicKeyParameters public_param=(DHPublicKeyParameters) DH_key.getPublic();
		BigInteger p=public_param.getParameters().getP();
		BigInteger q=public_param.getParameters().getQ();
		BigInteger g=public_param.getParameters().getG();
		
		TLV p_tlv=new TLV(TLV.TAG.DH_P,p.toByteArray());
		TLV q_tlv=new TLV(TLV.TAG.DH_Q,q.toByteArray());
		TLV g_tlv=new TLV(TLV.TAG.DH_G,g.toByteArray());
		
		try {
			p_tlv.sendTLV(getOut());
			q_tlv.sendTLV(getOut());
			g_tlv.sendTLV(getOut());
		} 
		catch (IOException e) {
			Service.log("Errore nell'invio dei parametri DH", 0);
			e.printStackTrace();
			return false;
		}
		
		this.state=States_Client.WAIT_DH_PARAM_CONFIRM;
		this.setExpected_tag(TLV.TAG.DH_PARAM_CONFIRM);
		return true;
	}

	
	public Boolean nextStep() {
		return null;
	}

	public String getState(){
		 return this.state.toString();
	}
	public TLV.TAG getExpected_tag() {
		return expected_tag;
	}
	public void setExpected_tag(TLV.TAG expected_tag) {
		this.expected_tag = expected_tag;
	}
	
	
}
