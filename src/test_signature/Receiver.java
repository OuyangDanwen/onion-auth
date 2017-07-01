import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Receiver {

	// Socket communication
	private ObjectOutputStream toSender;
	private ObjectInputStream fromSender;
	ServerSocket welcomeSkt;
	Socket skt;

	// Personal keys
	private PrivateKey rsaPriKey;
	private PublicKey rsaPubKey;
	private PrivateKey dhPriKey;
	private PublicKey dhPubKey;
	// Received keys from the other peer
	private PublicKey receivedDHPubKey;
	private PublicKey receivedRSAPubKey;

	private byte[] message;

	public static void main(String[] args) {
		Receiver receiver = new Receiver();
		receiver.run();
	}

	private void run() {
		try {
			int portNum = 9191;
			welcomeSkt = new ServerSocket(portNum);
			System.out.println("Receiver: Receiver listens at port " + portNum);
			skt = welcomeSkt.accept();
			toSender = new ObjectOutputStream(skt.getOutputStream());
			fromSender = new ObjectInputStream(skt.getInputStream());

			generateKeys();

			receiveDHPubKey();
			byte[] hashedSecretKey = hashSecretKey(generateSecretKey());
			byte[] signature = generateAndSignMessage(hashedSecretKey);
			sendMessageWithSignature(signature);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * =============== HELPER METHODS ===============
	 */

	// Generates a pair of DH and RSA private and public keys
	private void generateKeys() throws Exception {
		// DH key pair
		KeyPairGenerator keyPairGenDh = KeyPairGenerator.getInstance("DH");
		keyPairGenDh.initialize(1024);
		KeyPair keyPairDh = keyPairGenDh.generateKeyPair();
		dhPriKey = keyPairDh.getPrivate();
		dhPubKey = keyPairDh.getPublic();

		// RSA key pair
		KeyPairGenerator keyPairGenRsa = KeyPairGenerator.getInstance("RSA");
		keyPairGenRsa.initialize(1024);
		KeyPair keyPairRsa = keyPairGenRsa.generateKeyPair();
		rsaPriKey = keyPairRsa.getPrivate();
		rsaPubKey = keyPairRsa.getPublic();

		System.out.println("Receiver: Keys generated");
	}

	// Receives DH public key from the other peer
	private void receiveDHPubKey() throws Exception {
		receivedDHPubKey = (PublicKey) fromSender.readObject();
	}

	// Generate a secret key using the other peer's public key and own private key
	private byte[] generateSecretKey() throws Exception {
		KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
		keyAgreement.init(dhPriKey);
		keyAgreement.doPhase(receivedDHPubKey, true);

		byte[] rawSecretKey = keyAgreement.generateSecret();
		byte[] secretKey = new byte[16]; // 128-bit key
		System.arraycopy(rawSecretKey, 0, secretKey, 0, secretKey.length); // convert to 128-bit key
		System.out.println("Receiver: Secret key generated");

		return secretKey;
	}

	// Hashes the secret key using SHA-256 algorithm
	private byte[] hashSecretKey(byte[] secretKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(secretKey);
		System.out.println("Receiver: Secret key hashed using SHA-256");
		return md.digest();
	}

	// Message contains:
	// 1. DH public key
	// 2. RSA public key
	// 3. Hash value of the generated secret key
	public byte[] generateAndSignMessage(byte[] hashedSecretKey) throws Exception {
		byte[] a = dhPubKey.getEncoded(); // DH pub key
		byte[] b = rsaPubKey.getEncoded(); // RSA pub key
		byte[] c = hashedSecretKey; // hash of generated secret key

		message = new byte[a.length + b.length + c.length];
		System.arraycopy(a, 0, message, 0, a.length);
		System.arraycopy(b, 0, message, a.length, b.length);
		System.arraycopy(c, 0, message, a.length+b.length, c.length);

		System.out.println("Receiver: DH pub key length = " + a.length);
		System.out.println("Receiver: RSA pub key length = " + b.length);
		System.out.println("Receiver: Hashed secret key length = " + c.length);
		System.out.println("Receiver: message.length = " + message.length);

		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(rsaPriKey);
		sig.update(message);
		
		System.out.println("Receiver: Message with public keys and hashed value of secret key generated, and signed with RSA private key");
		return sig.sign();
	}

	// Sends the message, along with the signature, to the other peer
	private void sendMessageWithSignature(byte[] signature) throws Exception {
		toSender.write(message);
		toSender.flush();
		toSender.write(signature);
		toSender.flush();
	}

}