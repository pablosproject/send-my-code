import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Rappresenta un pacchetto di tipo Tag Length Value da mandare sul socket. Si implementano
 * i metodi che ritornano l'intero byte array, oppure solo alcuni, 
 * Verranno implementati i metodi che leggono da uno stream solo alcune parti, che serviranno
 * per l'autenticazione
 * @author paolotaglinani
 *
 */
public class TLV {

	public final static int INT_LENGTH_BYTE=4;
	private byte[] T;
	private byte[] L;
	private byte[] V;
	
	public enum TAG{
		//tag per lo scambio di IV
		IV(1),
		//set di tag scambio parametri DH
		DH_P(101),
		DH_G(102),
		DH_PARAM_CONFIRM(104),
		//secondo set di tag
		EKE_1(201),
		EKE_2(202),
		EKE_3(203),
		EKE_4(204);
		
		private int code;
		
		private TAG(int _code) {
	          this.code=_code;
	     }

		public int getCode() {
			return code;
		}
	}
	/**
	 * Costruttore che a cui bisogna passare i dati e il tipo di tag
	 * @param t il tag
	 * @param v il valore per il pacchetto corrente
	 */
	public TLV(TAG t,byte[] v){
		this.T=Service.intToBytes(t.getCode());
		this.L=Service.intToBytes(v.length+INT_LENGTH_BYTE*2);
		this.V=v;
	}
	
	public void sendTLV(DataOutputStream stream_out) throws IOException{
		byte[] to_send=Service.concatArray(this.T, this.L);
		to_send=Service.concatArray(to_send, this.V);
		stream_out.write(to_send);
	}
	
	public static int getT (DataInputStream stream) throws IOException{
		byte[] letto= new byte[4];
			stream.read(letto, 0, INT_LENGTH_BYTE);
		
		Integer letto_int=Service.byteToInt(letto);
		Service.log("Tag Letto: "+letto_int.toString(), 2);
		return Service.byteToInt(letto);	
	}
	
	public static byte[] getV (DataInputStream stream) throws IOException{
		byte[] lettoL= new byte[4];
		stream.read(lettoL, 0, INT_LENGTH_BYTE);
		Integer letto_int=Service.byteToInt(lettoL);
		byte[] v= new byte[(letto_int-INT_LENGTH_BYTE*2)];
		stream.read(v,0,(letto_int-INT_LENGTH_BYTE*2));
		
		return v;	
	}
	
	public static int getHostId(byte [] _read){

		byte[] received_host_id=new byte[INT_LENGTH_BYTE];
		received_host_id=Arrays.copyOfRange(_read, 0,INT_LENGTH_BYTE);
		return Service.byteToInt(received_host_id);
	}
	
}
	

