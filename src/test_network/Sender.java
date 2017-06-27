import java.io.File;
import java.io.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.SealedObject;
import java.security.spec.*;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public class Sender {
	private ObjectOutputStream toReceiver;
	private ObjectInputStream fromReceiver;
	private static final String SESSION_KEY_FILE = "sessionKey";
	private static final String PUBLIC_KEY_FILE = "public_key.der";
	private static final String CIPHERTEXT_FILE = "ciphertext";
	private static final String PLAINTEXT_FILE = "plaintext";
	private byte[] aesKey;
	private PublicKey pub;
	private int requestCounter = 0;

	enum MessageType {
		AUTH_SESSION_START(1), AUTH_SESSION_HS1(2), 
		AUTH_SESSION_INCOMING_HS1(3), AUTH_SESSION_HS2(4), 
		AUTH_SESSION_INCOMING_HS2(5), AUTH_LAYER_ENCRYPT(6),
		AUTH_LAYER_ENCRYPT_RESP(7), AUTH_LAYER_DECRYPT(8), 
		AUTH_LAYER_DECRYPT_RESP(9), AUTH_SESSION_CLOSE(10),
		AUTH_SESSION_ERROR(11);

		private int val;

		MessageType(int val) {
			this.val = val;
		}

		public int getVal() {
			return this.val;
		}
	}

	public static void main(String[] args) {
		Sender sender = new Sender();

		try {
			int receiverPortNum = 9191;
			String receiverIPAddress = "127.0.0.1";
			Socket skt = new Socket(receiverIPAddress, receiverPortNum);
			sender.toReceiver = new ObjectOutputStream(skt.getOutputStream());
			sender.fromReceiver = new ObjectInputStream(skt.getInputStream());

			File sessionKey = new File(SESSION_KEY_FILE);
			//read session key from file
			sender.readSessionKey(sessionKey);
			//read public key from file
			sender.pub = sender.getPub(PUBLIC_KEY_FILE);

			//encrypt session key with public key
			SealedObject encryptedSessionKey = sender.encryptSessionKey();
			//send the encrypted session key
			sender.sendSessionKey(encryptedSessionKey);

			File plaintext = new File("plaintext");

			File ciphertext = new File("ciphertext");
			if (ciphertext.createNewFile()){
		    	System.out.println("A new file \"ciphertext\" is created!");
		  	} else {
		    	System.out.println("File \"ciphertext\" already exists.");
		  	}


		  	//encrypt the plaintext and save the ciphertext
		  	sender.encrypt(plaintext, ciphertext);
		  	sender.sendCiphertext(plaintext);

			sender.sendAuthStart();



      } catch (Exception e) {
      	System.out.println(e.toString());
      }


	}

	private void sendSessionKey(SealedObject encryptedSessionKey) throws Exception {
        this.toReceiver.writeObject(encryptedSessionKey);
        this.toReceiver.flush();
	}

	private void sendCiphertext(File in) throws Exception {
		Scanner fromFile = new Scanner(in);
            
        int numLines = 0;
        ArrayList<String> text = new ArrayList<String>();

        while (fromFile.hasNextLine()) {
        	numLines++;
        	text.add(fromFile.nextLine());
        }

        this.toReceiver.writeInt(numLines);
        this.toReceiver.flush();

        for (int i = 0; i < numLines; i++) {
        	SealedObject encryptedText = encryptText(text.get(i));
        	this.toReceiver.writeObject(encryptedText);
        	this.toReceiver.flush();
        }
        
        fromFile.close();  // close input file stream
	}

	private void sendAuthStart() throws Exception {
		//16-byte size with padding, the size of the public key in this case
		byte[] keyBytes = pub.getEncoded();
		int size = keyBytes.length;
		this.toReceiver.writeInt(size);
		this.toReceiver.flush();
		System.out.println("Payload size is: " + size);
		this.toReceiver.write(new byte[12]);
		this.toReceiver.flush();


		//16-byte message type with padding
		this.toReceiver.writeInt(MessageType.AUTH_SESSION_START.getVal());
		System.out.println("Type value is: " + MessageType.AUTH_SESSION_START.getVal());
		this.toReceiver.flush();
		this.toReceiver.write(new byte[12]);
		this.toReceiver.flush();

		//reserved field of 32 bytes of 0s(reserved)
		this.toReceiver.write(new byte[32]);
		this.toReceiver.flush();

		//32-byte request ID with padding
		this.toReceiver.writeInt(requestCounter);
		System.out.println("Request ID is: " + requestCounter);
		this.toReceiver.flush();
		requestCounter++;
		this.toReceiver.write(new byte[28]);
		this.toReceiver.flush();

		//hostkey(public key) in DER format
		this.toReceiver.write(keyBytes);
		this.toReceiver.flush();

	}

	private void readSessionKey(File in) throws Exception {
		FileInputStream fis = new FileInputStream(in);
		this.aesKey = new byte[256/8];
		fis.read(aesKey);
	}

	private SealedObject encryptSessionKey() throws Exception {

		SealedObject sealedObj = null;
        Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // RSA imposes size restriction on the object being encrypted (117 bytes).
        // Instead of sealing a Key object which is way over the size restriction,
        // we shall encrypt AES key in its byte format (using getEncoded() method).           
        pkCipher.init(Cipher.ENCRYPT_MODE, this.pub);
        return new SealedObject(aesKey, pkCipher);       
	}

	private PublicKey getPub(String filename) throws Exception {
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}

	private void encrypt(File in, File out) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
    	CipherInputStream is = new CipherInputStream(
    		new FileInputStream(in), aesCipher);
    	FileOutputStream os = new FileOutputStream(out);
    	copy(is, os);
    	is.close();
    	os.close();
	}

	private void copy(InputStream is, OutputStream os) throws Exception {
		int i;
    	byte[] b = new byte[1024];
    	while ((i = is.read(b)) != -1) {
    		os.write(b, 0, i);
    	}
	}

	public SealedObject encryptText(String text) throws Exception {
            
        SealedObject sessionKeyObj = null;
        SecretKeySpec aesKeySpec = new SecretKeySpec(this.aesKey, "AES");
            
        // getInstance(crypto algorithm/feedback mode/padding scheme)
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
        sessionKeyObj = new SealedObject(text, aesCipher);
            
        return sessionKeyObj;
    }

}