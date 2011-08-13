import java.io.DataInputStream;
import java.io.DataOutputStream;


public abstract class Connection {

	private DataInputStream in;
	private DataOutputStream out;
	
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
