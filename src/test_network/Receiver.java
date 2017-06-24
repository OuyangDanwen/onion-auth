import java.io.File;
import java.io.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.*;
import javax.crypto.SealedObject;
import java.security.spec.*;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Receiver {
	private ObjectOutputStream toSender;
	private ObjectInputStream fromSender;
	ServerSocket welcomeSkt;  // wait for sender to connect
	Socket skt;
	private byte[] aesKey;
	SecretKeySpec aesKeySpec;
	private PrivateKey pri;
	private static final String PRIVATE_KEY_FILE = "private_key.der";
	private static final String CIPHERTEXT_FILE = "ciphertext";
	private static final String RECOVERED_PLAINTEXT_FILE = "recoveredPlaintext";

	public static void main(String[] args) {
		Receiver receiver = new Receiver();
		try {
			int portNum = 9191;
			receiver.welcomeSkt = new ServerSocket(portNum);
			System.out.println("Receiver listens at port " + portNum);
			receiver.skt = receiver.welcomeSkt.accept();
			receiver.toSender = new ObjectOutputStream(receiver.skt.getOutputStream());
			receiver.fromSender = new ObjectInputStream(receiver.skt.getInputStream());

			//read private key
			receiver.pri = receiver.getPri(PRIVATE_KEY_FILE);

			//receive encrypted session key and decrypt the session key
			receiver.receiveSessionKey();

			//decrypt the ciphertext
			//File ciphertext = new File(CIPHERTEXT_FILE);
			File recoveredPlaintext = new File(RECOVERED_PLAINTEXT_FILE);
			if (recoveredPlaintext.createNewFile()){
		    	System.out.println("A new file \"recoveredPlaintext\" is created!");
		  	} else {
		    	System.out.println("File \"recoveredPlaintext\" already exists.");
		  	}

		  	//TODO: receive the ciphertext from sender instead of reading it locally
		  	receiver.receiveCiphertext(recoveredPlaintext);

			//receiver.decrypt(ciphertext, recoveredPlaintext);

			receiver.welcomeSkt.close();
			receiver.skt.close();
		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}

	private void receiveSessionKey() throws Exception {
		
        SealedObject sessionKeyObj = (SealedObject)this.fromSender.readObject();
        
        Cipher pkCipher = Cipher.getInstance("RSA");
        pkCipher.init(Cipher.DECRYPT_MODE, this.pri);
        
        // receive an AES key in "encoded form" from Alice
        byte[] rawKey = (byte[])sessionKeyObj.getObject(pkCipher);
        // reconstruct AES key from encoded form
        this.aesKeySpec = new SecretKeySpec(rawKey, 0, rawKey.length, "AES");
	}

	private void receiveCiphertext(File out) throws Exception {
		PrintWriter pw = new PrintWriter(out);
		int numLines = fromSender.readInt();
        for (int i = 0; i < numLines; i++) {
            SealedObject encryptedText = (SealedObject) fromSender.readObject();
            String decryptedText = decryptText(encryptedText);
            pw.write(decryptedText, 0, decryptedText.length());
            pw.write('\n');
        }
        pw.flush();
        pw.close();
	}

	public String decryptText(SealedObject encryptedMsgObj) throws Exception{
            
        String plaintext = null;
        
   
        // Alice and Bob use the same AES key/transformation
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, this.aesKeySpec);

        plaintext = (String) encryptedMsgObj.getObject(aesCipher);
        
        return plaintext;
    }



	private void decrypt(File in, File out) throws Exception{
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, this.aesKeySpec);
		FileInputStream is = new FileInputStream(in);
		CipherOutputStream os = new CipherOutputStream(
			new FileOutputStream(out), aesCipher);
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


	public PrivateKey getPri(String filename) throws Exception {
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	    PKCS8EncodedKeySpec spec =
	      new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}


}