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
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class PeerOnionAuth {
	final private ObjectOutputStream toOnion;
	final private ObjectInputStream fromOnion;
	final private ServerSocket welcomeSkt;  // wait for sender to connect
	final private Socket skt;
	private byte[] aesKey;
	private SecretKeySpec aesKeySpec;
	private PrivateKey dhPri;
	private PublicKey dhPub;
	private PublicKey hostkey;
	final private KeyFactory rsaKeyFactory;
	final private KeyFactory aesKeyFactory;
	final private Cipher pkCipher;
	final private Cipher aesCipher;

	public PeerOnionAuth(int portNum) throws Exception {
		//set up
		//1.network
		this.welcomeSkt = new ServerSocket(portNum);
		System.out.println("Onion Authentication listens at port " + portNum);
		this.skt = this.welcomeSkt.accept();
		System.out.println("Incoming connection from Onion accepted");
		this.toOnion = new ObjectOutputStream(this.skt.getOutputStream());
		this.fromOnion = new ObjectInputStream(this.skt.getInputStream());
		//2.crypto
	    this.rsaKeyFactory = KeyFactory.getInstance("RSA");
		this.aesKeyFactory = KeyFactory.getInstance("AES");
		this.aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		this.pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	}

	public void readHostKey(String hostkeyFile) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(hostkeyFile));
	    final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    this.hostkey = kf.generatePublic(spec);
	}

	public void handleAuthStart() throws Exception {

	}

	private void sendHS1() throws Exception {

	}

	public void handleIncomingHS1() throws Exception {

	}

	private void sendHS2() throws Exception {

	}

	public void handleIncomingHS2() throws Exception {

	}

	public void handlelayerEncrypt() throws Exception {

	}

	private void sendLayerEncryptRESP() {

	}

	public void handlelayerDecrypt() throws Exception {

	}

	private void sendLayerDecryptRESP() throws Exception {

	}

	public void handleAuthClose() throws Exception {

	}

	private void sendAuthError() throws Exception {

	}

}