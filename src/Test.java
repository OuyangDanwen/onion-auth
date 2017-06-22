import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import java.util.Scanner;
import javax.crypto.spec.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.lang.*;


public class Test {
	private static String CIPHERTEXT_FILE = "ciphertext";
	private static String RECOVERED_PLAINTEXT_FILE = "recoveredPlaintext";
	private static String PLAINTEXT_FILE = "plaintext";
	private static String PRIVATE_KEY_FILE = "private_key.der";
	private static String PUBLIC_KEY_FILE = "public_key.der";
	private static String ENCRYPTED_SESSION_KEY_FILE = "encryptedSessionKey";
	private Cipher aesCipher;
	private Cipher pkCipher;
	private SecretKeySpec aeskeySpec;
	private PublicKey pub;
	private PrivateKey pri;
	private byte[] aesKey;

	public static void main(String[] args) {

		try {

			Test test = new Test();


			//Generate a random 256-bit AES session key
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
	    	kgen.init(256);
	    	SecretKey key = kgen.generateKey();
	    	test.aesKey = key.getEncoded();
	    	//Generate a 2048-bit RSA private key 
	    	String c1 = "openssl genrsa -out private_key.pem 2048";
	    	Process p1 = Runtime.getRuntime().exec(c1);
	    	p1.waitFor();
	    	//Convert and output private key to PKCS#8 format
	    	String c2 = "openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt";
	    	Process p2 = Runtime.getRuntime().exec(c2);
	    	p2.waitFor();
	    	//Output public key in DER format
	    	String c3 = "openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der";
	    	Process p3 = Runtime.getRuntime().exec(c3);
	    	p3.waitFor();


	    	//Read public key and private key
	    	test.pri = test.getPri(PRIVATE_KEY_FILE);
	    	test.pub = test.getPub(PUBLIC_KEY_FILE);
	    	test.pkCipher = Cipher.getInstance("RSA");
	    	File encryptedSessionKey = new File(ENCRYPTED_SESSION_KEY_FILE);
	    	if (encryptedSessionKey.createNewFile()){
	        	System.out.println("A new file \"encryptedSessionKey\" is created!");
	      	} else {
	        	System.out.println("File \"encryptedSessionKey\" already exists.");
	      	}
			//Encrypt session key with public key
	    	test.encryptSessionKey(encryptedSessionKey);
	    	//Decrypt session key with private key
	    	test.decryptSessionKey(encryptedSessionKey);


	    	//Use the decrypted session key to encrypt and decrypt a given text file
	    	File plaintext = new File(PLAINTEXT_FILE);

	    	File recoveredPlaintext = new File(RECOVERED_PLAINTEXT_FILE);
	    	if (recoveredPlaintext.createNewFile()){
	        	System.out.println("A new file \"recoveredPlaintext\" is created!");
	      	} else {
	        	System.out.println("File \"recoveredPlaintext\" already exists.");
	      	}

	    	File ciphertext = new File(CIPHERTEXT_FILE);
	    	if (ciphertext.createNewFile()){
	        	System.out.println("A new file \"ciphertext\" is created!");
	      	} else {
	        	System.out.println("File \"ciphertext\" already exists.");
	      	}

	    	test.aesCipher = Cipher.getInstance("AES");
	    	test.encrypt(plaintext, ciphertext);
	    	test.decrypt(ciphertext, recoveredPlaintext);     

		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}

	private void copy(InputStream is, OutputStream os) throws Exception {
		int i;
    	byte[] b = new byte[1024];
    	while ((i = is.read(b)) != -1) {
    		os.write(b, 0, i);
    	}
	}

	private void encrypt(File in, File out) throws Exception{
		aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
    	CipherInputStream is = new CipherInputStream(
    		new FileInputStream(in), aesCipher);
    	FileOutputStream os = new FileOutputStream(out);
    	copy(is, os);
    	is.close();
    	os.close();
	}

	private void decrypt(File in, File out) throws Exception{
		aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);
		FileInputStream is = new FileInputStream(in);
		CipherOutputStream os = new CipherOutputStream(
			new FileOutputStream(out), aesCipher);
		copy(is, os);
		is.close();
		os.close();
	}

	private void encryptSessionKey(File out) throws Exception {
		pkCipher.init(Cipher.ENCRYPT_MODE, pub);
		CipherOutputStream os = new CipherOutputStream(
			new FileOutputStream(out), pkCipher);
		os.write(aesKey);
		os.close();
	}

	private void decryptSessionKey(File in) throws Exception {
		pkCipher.init(Cipher.DECRYPT_MODE, pri);
		aesKey = null;
	    aesKey = new byte[256/8];
	    CipherInputStream is = new CipherInputStream(new FileInputStream(in), pkCipher);
	    is.read(aesKey);
	    aeskeySpec = new SecretKeySpec(aesKey, "AES");
	    is.close();
	}

	public PrivateKey getPri(String filename) throws Exception {
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	    PKCS8EncodedKeySpec spec =
	      new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}

	public PublicKey getPub(String filename) throws Exception {
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}
}