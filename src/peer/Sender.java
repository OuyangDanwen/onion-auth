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
	private OutputStream toReceiver;
	private InputStream fromReceiver;
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
			sender.toReceiver = skt.getOutputStream();
			sender.fromReceiver = skt.getInputStream();

			sender.start();
			sender.receivePub();
			sender.sendDH();
			sender.receiveDHPayload();

      } catch (Exception e) {
      	System.out.println(e.toString());
      }


	}

	private void start() throws Exception {
		this.toReceiver.write(new byte[4]);//just write 100 to start a conversation
		this.toReceiver.flush();
	}

	private void receivePub() throws Exception {
		byte[] peerRsaPubBytes = new byte[550];
		this.fromReceiver.read(peerRsaPubBytes, 0, 550);
		this.peerRsaPub = KeyFactory.getInstance("RSA").generatePublic(
			new X509EncodedKeySpec(peerRsaPubBytes));
		//this.peerRsaPub = (PublicKey)this.fromReceiver.readObject();
		System.out.println("rsa key size: " + this.peerRsaPub.getEncoded().length);

	}


	private void sendDH() throws Exception {
		//generate DH key pairs
		this.generateDHKeyPair();


		//send HS2 payload (session key hash + peer DH public key)
		this.toReceiver.write(this.dhPub.getEncoded());
		this.toReceiver.flush();

	}

	private void receiveDHPayload() throws Exception {
		byte[] peerDhPubBytes = new byte[813];
		this.fromReceiver.read(peerDhPubBytes, 0, 813);
		this.peerDhPub = KeyFactory.getInstance("DiffieHellman").generatePublic(new X509EncodedKeySpec(peerDhPubBytes));
		//this.peerDhPub = (PublicKey)this.fromReceiver.readObject();
		System.out.println("dh key size: " + this.peerDhPub.getEncoded().length);
		byte[] digest = new byte[32];
		this.fromReceiver.read(digest, 0, 32);
		byte[] signature = new byte[512];
		this.fromReceiver.read(signature, 0, 512);

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
		keyPairGenerator.initialize(2048);
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