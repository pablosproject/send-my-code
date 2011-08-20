import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.InvalidCipherTextException;


public abstract class FSM 
{
	private DataInputStream in;
	private DataOutputStream out;
	private int host_id;
	private int brother_host_id;
	private AESCipher AES;
	
	public FSM(DataInputStream _in, DataOutputStream _out, int _host_id, int _brother_host_id, String pass){
		this.setIn(_in);
		this.setOut(_out);
		this.setHost_id(_host_id);
		this.setBrother_host_id(_brother_host_id);
		this.setAES(new AESCipher(pass));
		this.AES.initChiper(true);
	}
	
	public abstract boolean start() throws IOException;
	public abstract boolean nextStep() throws IOException, InvalidCipherTextException, 
	IncorrectHostnameException, IncorrectNounceException, ResetMachineException, IncorrectTagException;
	
	public void sendReset(){
		byte[] vuoto=new byte[0];
		TLV reset=new TLV(TLV.TAG.RESET,vuoto);
		try {
			reset.sendTLV(this.getOut());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public DataInputStream getIn() {
		return in;
	}

	public void setIn(DataInputStream in) {
		this.in = in;
	}

	public DataOutputStream getOut() {
		return out;
	}

	public void setOut(DataOutputStream out) {
		this.out = out;
	}

	public int getHost_id() {
		return host_id;
	}

	public void setHost_id(int host_id) {
		this.host_id = host_id;
	}

	public int getBrother_host_id() {
		return brother_host_id;
	}

	public void setBrother_host_id(int brother_host_id) {
		this.brother_host_id = brother_host_id;
	}

	public AESCipher getAES() {
		return AES;
	}

	public void setAES(AESCipher aES) {
		AES = aES;
	}
	
	
}
