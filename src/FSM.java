import java.io.DataInputStream;
import java.io.DataOutputStream;


public abstract class FSM 
{
	private DataInputStream in;
	private DataOutputStream out;
	
	public FSM(DataInputStream _in, DataOutputStream _out){
		this.setIn(_in);
		this.setOut(_out);
	}
	
	public abstract boolean start();
	public abstract Boolean nextStep();
	

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
	
	
}
