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
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


public class Sender {
	private ObjectOutputStream toReceiver;
	private ObjectInputStream fromReceiver;
	private PublicKey dhPub;
	private PrivateKey dhPri;
	private PublicKey peerRsaPub;
	private PublicKey peerDhPub;

	public static void main(String[] args) {
		Sender sender = new Sender();

		try {
			int receiverPortNum = 9191;
			String receiverIPAddress = "127.0.0.1";
			Socket skt = new Socket(receiverIPAddress, receiverPortNum);
			sender.toReceiver = new ObjectOutputStream(skt.getOutputStream());
			sender.fromReceiver = new ObjectInputStream(skt.getInputStream());

			sender.start();
			sender.receivePub();
			sender.sendDH();
			sender.receiveDHPayload();




      } catch (Exception e) {
      	System.out.println(e.toString());
      }


	}

	private void start() throws Exception {
		this.toReceiver.writeInt(100);
		this.toReceiver.flush();
	}

	private void receivePub() throws Exception {
		this.peerRsaPub = (PublicKey)this.fromReceiver.readObject();

	}


	private void sendDH() throws Exception {
		//generate DH key pairs
		this.generateDHKeyPair();


		//send HS2 payload (session key hash + peer DH public key)
		this.toReceiver.writeObject(this.dhPub);
		this.toReceiver.flush();

	}

	private void receiveDHPayload() throws Exception {
		this.peerDhPub = (PublicKey)this.fromReceiver.readObject();
		byte[] digest = new byte[32];
		this.fromReceiver.read(digest, 0, 32);
		int signatureSize = this.fromReceiver.readInt();
		byte[] signature = new byte[signatureSize];
		System.out.println("signature size: " + signatureSize);
		this.fromReceiver.read(signature, 0, signatureSize);

		SecretKeySpec sessionKey = this.generateCommonSecretKey(this.peerDhPub);

		//verify digest
		MessageDigest md5 = MessageDigest.getInstance("SHA-256");
		md5.update(sessionKey.getEncoded());
		byte[] computedDigest = md5.digest();
		md5.reset();
		if (!Arrays.equals(digest, computedDigest)) {
			System.out.println("Session key hash does not match!");
		} else {
			System.out.println("Session key hash matches, okay to proceed!");
		}


		//verify signature
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(this.peerRsaPub);
		byte[] payload = new byte[digest.length + this.peerDhPub.getEncoded().length];
		System.out.println("payload size: " + payload.length);
		System.arraycopy(digest, 0, payload, 0, digest.length);
		System.arraycopy(this.peerDhPub.getEncoded(), 0, payload, 
			digest.length, this.peerDhPub.getEncoded().length);
		sig.update(payload);
		if (!sig.verify(signature)) {
			System.out.println("Payload signature does not match!");
		} else {
			System.out.println("Payload signature matches, okay to proceed!");
		}

	}


	private void generateDHKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		this.dhPri = keyPair.getPrivate();
		this.dhPub = keyPair.getPublic();
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