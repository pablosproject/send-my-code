import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;


public class FSM_Server extends FSM {
	
	private enum States_Server{
		WAIT_EKE1,
		WAIT_EKE3,
	}

	private DHParameters parameter;
	private States_Server state;
	

	
	public FSM_Server(DataOutputStream _out, DataInputStream _in)
	{
		super(_in, _out);
	}
	
	/**
	 * Inizia il protocollo prelevando dallo stream i parametri per DH
	 */
	public boolean start() {
		
		
		try{
			BigInteger p;
			BigInteger q;
			BigInteger g;
			
			int codice_P=TLV.getT(getIn());
			if (codice_P==TLV.TAG.DH_P.getCode()){
				byte[] letto_p=TLV.getV(getIn());
			    p=new BigInteger(letto_p);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perchè gli altri tag non li leggo
			}

			int codice_Q=TLV.getT(getIn());
			if (codice_Q==TLV.TAG.DH_G.getCode()){
				byte[] letto_q=TLV.getV(getIn());
				q=new BigInteger(letto_q);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perchè gli altri tag non li leggo
			}

			int codice_G=TLV.getT(getIn());
			if (codice_G==TLV.TAG.DH_G.getCode()){
				byte[] letto_g=TLV.getV(getIn());
				g=new BigInteger(letto_g);
			}
			else{
				Service.log("Errore nella lettura dei parametri DH. Tag iniziale errato", 1);
				return false;
				//se si esce bisogna poi svuotare lo stream di input perchè gli altri tag non li leggo
			}
			
			this.parameter= new DHParameters(p,q,g);

		}
		catch(IOException e){
			Service.log("Errore nella lettura dallo stream input, durante trasmissione" +
					"dei parametri DH.", 1);
		}
		
		byte[] vuoto=new byte[0];
		TLV conferma=new TLV(TLV.TAG.DH_PARAM_CONFIRM,vuoto);
		try {
			conferma.sendTLV(getOut());
		} catch (IOException e) {
			Service.log("Errore nell'invio conferma paramteri DH", 1);
			e.printStackTrace();
			return false;
		}
			
		this.state=States_Server.WAIT_EKE1;
		return true;
	}

	@Override
	public Boolean nextStep() {
		// TODO Auto-generated method stub
		return null;
	}

}
