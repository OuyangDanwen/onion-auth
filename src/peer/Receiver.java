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
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
public class Receiver {
	private DataOutputStream toSender;
	private DataInputStream fromSender;
	ServerSocket welcomeSkt;  // wait for sender to connect
	Socket skt;
	private PublicKey rsaPub;
	private PrivateKey rsaPri;
	private PublicKey dhPub;
	private PrivateKey dhPri;
	private SecretKeySpec sessionKey;
	private MessageDigest md5;
	private PublicKey peerDhPub;
	

	public static void main(String[] args) {
		Receiver receiver = new Receiver();
		try {
			int portNum = 9191;
			receiver.welcomeSkt = new ServerSocket(portNum);
			System.out.println("Receiver listens at port " + portNum);
			receiver.skt = receiver.welcomeSkt.accept();
			receiver.toSender = new DataOutputStream(receiver.skt.getOutputStream());
			receiver.fromSender = new DataInputStream(receiver.skt.getInputStream());
			receiver.md5 = MessageDigest.getInstance("SHA-256");

		  	receiver.start();
		  	receiver.sendPub();
		  	receiver.receiveDH();
		  	receiver.sendDHPayload();

			receiver.skt.close();
		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}

	private void start() throws Exception {
		this.fromSender.read(new byte[4]);
		//System.out.println("Start value: " + start);

	}

	private void sendPub() throws Exception {
		this.generateRSAKeyPair();
		this.generateDHKeyPair();
		this.toSender.write(this.rsaPub.getEncoded());
		this.toSender.flush();
	}

	private void receiveDH() throws Exception {
		byte[] peerDhPubBytes = new byte[813];
		this.fromSender.read(peerDhPubBytes, 0, 813);
		this.peerDhPub = KeyFactory.getInstance("DiffieHellman").generatePublic(
			new X509EncodedKeySpec(peerDhPubBytes));
		//this.peerDhPub = (PublicKey)this.fromSender.readObject();
		this.sessionKey = this.generateCommonSecretKey(this.peerDhPub);
	}

	private void sendDHPayload() throws Exception {
		//generate handshake payload signed (session key hash + own DH public key)

		//generate key hansh
		this.md5.update(this.sessionKey.getEncoded());
		byte[] digest = this.md5.digest();
		System.out.println("Digest size: " + digest.length);
		this.md5.reset();

		//generate signature
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(this.rsaPri);
		byte[] payload = new byte[digest.length + this.dhPub.getEncoded().length];
		System.arraycopy(digest, 0, payload, 0, digest.length);
		System.arraycopy(this.dhPub.getEncoded(), 0, payload, digest.length, this.dhPub.getEncoded().length);
		dsa.update(payload);
		byte[] signature = dsa.sign();

		this.toSender.write(this.dhPub.getEncoded());
		this.toSender.flush();
		this.toSender.write(digest); //16 bytes
		this.toSender.flush();
		this.toSender.write(signature);
		this.toSender.flush();
	}

	private void generateDHKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		this.dhPri = keyPair.getPrivate();
		this.dhPub = keyPair.getPublic();
	}

	private void generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		this.rsaPri = keyPair.getPrivate();
		this.rsaPub = keyPair.getPublic();
		System.out.println("receiver rsa key size: " + this.rsaPub.getEncoded().length);
	}

	private SecretKeySpec generateCommonSecretKey(PublicKey peerDhPub) throws Exception {
		//generate the common secret
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(this.dhPri);
        keyAgreement.doPhase(peerDhPub, true);

		//construct the 256-bit common AES key 
		byte[] rawAESKey = new byte[32];
		byte[] rawSecret = keyAgreement.generateSecret();
		System.arraycopy(rawSecret, 0, rawAESKey, 0, rawAESKey.length);
		return new SecretKeySpec(rawAESKey, 0, rawAESKey.length, "AES");
	}



}