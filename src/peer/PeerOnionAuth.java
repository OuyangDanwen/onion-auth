import java.io.File;
import java.io.*;
import java.io.PrintWriter;
import java.net.Socket;
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
	private DataOutputStream toOnion;
	private DataInputStream fromOnion;
	private ServerSocket welcomeSkt;  // wait for sender to connect
	private Socket skt;
	private PrivateKey dhPri;
	private PublicKey dhPub;
	private KeyFactory rsaKeyFactory;
	private MessageDigest sha256;
	private HashMap<Integer, SecretKeySpec> sessionKeyMap; // map session ID to session key
	private SecureRandom prng;
	private PublicKey peerHostkey;
	private PrivateKey rsaPri;
	private PublicKey rsaPub;

	private int requestID = 0;

	public PeerOnionAuth() throws Exception {
		//crypto set up
	    this.rsaKeyFactory = KeyFactory.getInstance("RSA");
		this.sessionKeyMap = new HashMap<Integer, SecretKeySpec>();
		this.prng = SecureRandom.getInstance("SHA1PRNG");
		this.sha256 = MessageDigest.getInstance("SHA-256");
		this.generateRSAKeyPair();
	}

	public void listenForConnection(int portNum) throws Exception {
		this.welcomeSkt = new ServerSocket(portNum);
		System.out.println("Onion Authentication listens at port " + portNum);
		this.skt = this.welcomeSkt.accept();
		System.out.println("Incoming connection from Onion accepted");
		this.toOnion = new DataOutputStream(this.skt.getOutputStream());
		this.fromOnion = new DataInputStream(this.skt.getInputStream());
		
		do {
			receiveMessage();
		} while (true);

	}

	public void readHostKey(String hostkeyFile) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(hostkeyFile));
	    final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    this.peerHostkey = kf.generatePublic(spec);
	}

	private void receiveMessage() throws Exception {
		//read 16-bit payload size
		byte[] sizeBytes = new byte[3];
		byte[] bytes = new byte[2];
		this.fromOnion.read(bytes, 0, 2);
		System.arraycopy(bytes, 0, sizeBytes, 1, bytes.length);
		int size = new BigInteger(sizeBytes).intValue();

		//read 16-bit message type
		byte[] typeBytes = new byte[2];
		this.fromOnion.read(typeBytes, 0, 2);
		int typeVal = new BigInteger(typeBytes).intValue();
		MessageType type = MessageType.values()[typeVal];

		switch(type) {
			case AUTH_SESSION_START: 
				handleAuthStart(size);
				break;
			case AUTH_SESSION_INCOMING_HS1: 
				handleIncomingHS1(size);
				break;
			case AUTH_SESSION_INCOMING_HS2: 
				handleIncomingHS2(size);
				break;
			case AUTH_LAYER_ENCRYPT: 
				handleLayerEncrypt(size);
				break;
			case AUTH_LAYER_DECRYPT: 
				handleLayerDecrypt(size);
				break;
			case AUTH_CIPHER_ENCRYPT: 
				byte[] reservedBytes = new byte[4];
				this.fromOnion.read(reservedBytes);
				handleCipherEncrypt(size, reservedBytes[3] & 1);
				break;
			case AUTH_CIPHER_DECRYPT: 
				handleCipherDecrypt(size);
				break;
			case AUTH_SESSION_CLOSE:
				handleSessionClose();
				break;
		}

	}

	// ========================================================================================
	//										API METHODS	
	// ========================================================================================


	public void handleAuthStart(int size) throws Exception {
		//read 32-bit reserved field
		byte[] reservedBytes = new byte[4];
		this.fromOnion.read(reservedBytes, 0, 4);

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		this.fromOnion.read(requestIDBytes, 0, 4);
		int requestID = new BigInteger(requestIDBytes).intValue();

		//read the hostkey(public key) as an object and save it for future use
		int peerHostkeySize = size - 12;
		byte[] peerHostkeyBytes = new byte[peerHostkeySize];
		this.fromOnion.read(peerHostkeyBytes, 0, peerHostkeySize);
		this.peerHostkey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(peerHostkeyBytes));

		//verify the size of the peer hostkey
		if (this.peerHostkey.getEncoded().length != size - 12) {
			System.out.println("Hostkey size size does not match!");
		} else {
			System.out.println("Hostkey size check passed, okay to proceed!");
		}

		//reply to SESSION AUTH START
		this.sendHS1(requestID);
	}

	private void sendHS1(int requestID) throws Exception {
		//16-bit size, in this case the size of the handshake payload
		this.generateDHKeyPair();
		byte[] dhPubBytes = this.dhPub.getEncoded();
		int size = 12 + dhPubBytes.length;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_SESSION_HS1.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit reserved field of 0s
		this.toOnion.write(new byte[2]);
		this.toOnion.flush();

		//16-bit session ID
		int sessionID = this.prng.nextInt((1 << 16) - 1);
		byte[] sessionIDBytes = ByteBuffer.allocate(4).putInt(sessionID).array();
		this.toOnion.write(Arrays.copyOfRange(sessionIDBytes, 2, 4));
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//handshake payload
		this.toOnion.write(dhPubBytes);
		this.toOnion.flush();

	}

	public void handleIncomingHS1(int size) throws Exception {
		//read 32-bit reserved field
		byte[] reservedBytes = new byte[4];
		this.fromOnion.read(reservedBytes, 0, 4);

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		this.fromOnion.read(requestIDBytes, 0, 4);
		int requestID = new BigInteger(requestIDBytes).intValue();

		//read HS1 handshake payload
		int peerDhPubSize = size - 12;
		byte[] peerDhPubBytes = new byte[peerDhPubSize];
		this.fromOnion.read(peerDhPubBytes, 0, size - 12);
		PublicKey peerDhPub = KeyFactory.getInstance("DiffieHellman").generatePublic(
			new X509EncodedKeySpec(peerDhPubBytes));

		//verify the size of the payload
		if (peerDhPub.getEncoded().length != size - 12) {
			System.out.println("Peer DH public key size does not match!");
		} else {
			System.out.println("Peer DH public key size check passed, okay to proceed!");
		}

		//generate common session key
		SecretKeySpec aesKeySpec = this.generateCommonSecretKey(peerDhPub);

		//reply to INCOMING HS1
		int sessionID = this.prng.nextInt((1 << 16) - 1);
		this.sessionKeyMap.put(sessionID, aesKeySpec);
		this.sendHS2(sessionID, requestID);
	}

	private void sendHS2(int sessionID, int requestID) throws Exception {
		
		//generate handshake payload signed (session key hash + own DH public key)

		//generate key hash
		SecretKeySpec aesKeySpec = this.sessionKeyMap.get(sessionID);
		this.sha256.update(aesKeySpec.getEncoded());
		byte[] digest = this.sha256.digest();
		this.sha256.reset();

		//generate signature
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(this.rsaPri);
		byte[] payload = new byte[digest.length + this.dhPub.getEncoded().length];
		System.arraycopy(digest, 0, payload, 0, digest.length);
		System.arraycopy(this.dhPub.getEncoded(), 0, payload, digest.length, this.dhPub.getEncoded().length);
		dsa.update(payload);
		byte[] signature = dsa.sign();

		//16-bit size
		int size = signature.length + this.dhPub.getEncoded().length + digest.length + 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_SESSION_HS2.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit reserved field
		this.toOnion.write(new byte[2]);
		this.toOnion.flush();

		//16-bit session ID
		byte[] sessionIDBytes = ByteBuffer.allocate(4).putInt(sessionID).array();
		this.toOnion.write(Arrays.copyOfRange(sessionIDBytes, 2, 4));
		this.toOnion.flush();

		//32-request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//write the payload and signature
		this.toOnion.write(this.dhPub.getEncoded());
		this.toOnion.flush();
		this.toOnion.write(digest);
		this.toOnion.flush();
		this.toOnion.write(signature);
		this.toOnion.flush();
	}

	public void handleIncomingHS2(int size) throws Exception {
		//read 16-bit reserved field
		byte[] reservedBytes = new byte[2];
		this.fromOnion.read(reservedBytes, 0, 2);

		//read 16-bit session ID
		byte[] sessionIDBytes = new byte[3];
		this.fromOnion.read(sessionIDBytes, 0, 2);
		int sessionID = new BigInteger(sessionIDBytes).intValue();

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		int requestID = this.fromOnion.read(requestIDBytes, 0, 4);

		//read HS2 payload (session key hash + peer DH public key)
		int peerDhPubSize = size - 12 - 32 - 512;
		byte[] peerDhPubBytes = new byte[peerDhPubSize];
		this.fromOnion.read(peerDhPubBytes, 0, peerDhPubSize);
		PublicKey peerDhPub = KeyFactory.getInstance("DiffieHellman").generatePublic(
			new X509EncodedKeySpec(peerDhPubBytes));
		byte[] digest = new byte[32];
		this.fromOnion.read(digest, 0, 32);
		byte[] signature = new byte[512];
		this.fromOnion.read(signature, 0, 512);

		//verify payload size
		if (!(peerDhPub.getEncoded().length + signature.length + digest.length + 12 == size)) {
			System.out.println("Handshake payload does not match!");
		} else {
			System.out.println("Handshake payload size matches, okay to proceed!");
		}


		//generate common session key
		SecretKeySpec aesKeySpec = this.generateCommonSecretKey(peerDhPub);

		//verify key hash
		this.sha256.update(aesKeySpec.getEncoded());
		byte[] computedDigest = this.sha256.digest();
		this.sha256.reset();
		if (!Arrays.equals(digest, computedDigest)) {
			System.out.println("Session key hash does not match!");
		} else {
			System.out.println("Session key hash matches, okay to proceed!");
		}

		//verify signature
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(this.rsaPub);
		byte[] payload = new byte[digest.length + peerDhPub.getEncoded().length];
		System.arraycopy(digest, 0, payload, 0, digest.length);
		System.arraycopy(peerDhPub.getEncoded(), 0, payload, 
			digest.length, peerDhPub.getEncoded().length);
		sig.update(payload);
		if (!sig.verify(signature)) {
			System.out.println("Payload signature does not match!");
		} else {
			System.out.println("Payload signature matches, okay to proceed!");
		}

		//add the session key to the key map
		this.sessionKeyMap.put(sessionID, aesKeySpec);
	}



	public void handleLayerEncrypt(int size) throws Exception {
		//read 16-bit reserved field
		byte[] reservedBytes = new byte[4];
		this.fromOnion.read(reservedBytes);

		//read number of layers
		byte[] numLayersBytes = new byte[2];
		numLayersBytes[1] = reservedBytes[2];
		int numLayers = new BigInteger(numLayersBytes).intValue();

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		int requestID = this.fromOnion.read(requestIDBytes, 0, 4);

		//read all session IDs and get corresponding keys
		ArrayList<SecretKeySpec> sessionKeys = new ArrayList<SecretKeySpec>();
		ArrayList<Integer> sessionIDs = new ArrayList<Integer>();
		for (int i = 0; i < numLayers; i++) {
			byte[] sessionIDBytes = new byte[3];
			this.fromOnion.read(sessionIDBytes, 0, 2);
			int sessionID = new BigInteger(sessionIDBytes).intValue();
			sessionIDs.add(sessionID);
			sessionKeys.add(this.sessionKeyMap.get(sessionID));
		}

		//read cleartext payload
		byte[] payload = new byte[size - 12 - numLayers * 2];
		this.fromOnion.read(payload, 0, payload.length);

		//get hash of the cleartext payload
		byte[] hashOrigPayload = this.hash(payload);

		//layer encrypt payload
		byte[] encPayload = this.layerEncrypt(sessionKeys, payload);

		// append the hash of the cleartext to the end of the encrypted payload
		byte[] encPayloadWithOrigHash = new byte[encPayload.length + hashOrigPayload.length];
		System.arraycopy(encPayload, 0, encPayloadWithOrigHash, 0, encPayload.length);
		System.arraycopy(hashOrigPayload, 0, encPayloadWithOrigHash, encPayload.length, hashOrigPayload.length);

		this.sendLayerEncryptRESP(requestID, encPayloadWithOrigHash);

	}

	private void sendLayerEncryptRESP(int requestID, byte[] encPayloadWithOrigHash) throws Exception {
		//16-bit size
		int size = encPayloadWithOrigHash.length + 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_LAYER_ENCRYPT_RESP.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//32-bit reserved field
		this.toOnion.write(new byte[4]);
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//write encrypted payload
		this.toOnion.write(encPayloadWithOrigHash);
		this.toOnion.flush();

	}

	public void handleLayerDecrypt(int size) throws Exception {
		//read 16-bit reserved field
		byte[] reservedBytes = new byte[4];
		this.fromOnion.read(reservedBytes);

		//read number of layers
		byte[] numLayersBytes = new byte[2];
		numLayersBytes[1] = reservedBytes[2];
		int numLayers = new BigInteger(numLayersBytes).intValue();

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		int requestID = this.fromOnion.read(requestIDBytes, 0, 4);

		//read all session IDs and get corresponding keys
		ArrayList<SecretKeySpec> sessionKeys = new ArrayList<SecretKeySpec>();
		for (int i = 0; i < numLayers; i++) {
			byte[] sessionIDBytes = new byte[3];
			this.fromOnion.read(sessionIDBytes, 0, 2);
			int sessionID = new BigInteger(sessionIDBytes).intValue();
			sessionKeys.add(this.sessionKeyMap.get(sessionID));
		}

		//read encrypted payload
		byte[] encPayload = new byte[size - 12 - (numLayers * 2) - 32];
		this.fromOnion.read(encPayload, 0, encPayload.length);

		// read hash value of original cleartext payload; not used here
		byte[] hashOrigPayload = new byte[32];
		this.fromOnion.read(hashOrigPayload, 0, hashOrigPayload.length);

		//layer decrypt encrypted payload
		byte[] decPayload = this.layerDecrypt(sessionKeys, encPayload);

		this.sendLayerDecryptRESP(requestID, decPayload);
	}

	private void sendLayerDecryptRESP(int requestID, byte[] decPayload) throws Exception {
		//16-bit size
		int size = decPayload.length + 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_LAYER_DECRYPT_RESP.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//32-bit reserved field
		this.toOnion.write(new byte[4]);
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//write decrypted payload
		this.toOnion.write(decPayload);
		this.toOnion.flush();

	}

	public void handleCipherEncrypt(int size, int flag) throws Exception {
		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		int requestID = this.fromOnion.read(requestIDBytes, 0, 4);

		//read 16-bit session ID
		byte[] sessionIDBytes = new byte[3];
		this.fromOnion.read(sessionIDBytes, 0, 2);
		int sessionID = new BigInteger(sessionIDBytes).intValue();

		byte[] payload;
		byte[] hashOrigPayload = new byte[32];
		if (flag == 1) { // already-encrypted payload
			//read encrypted payload
			payload = new byte[size - 14 - 32];
			this.fromOnion.read(payload, 0, payload.length);

			// read hash value of original cleartext payload
			this.fromOnion.read(hashOrigPayload, 0, hashOrigPayload.length);
		} else { // cleartext
			// read cleartext payload
			payload = new byte[size - 14];
			this.fromOnion.read(payload, 0, payload.length);

			// obtain the hash of the cleartext payload
			hashOrigPayload = this.hash(payload);
		}

		//get session key
		SecretKeySpec sessionKey = sessionKeyMap.get(sessionID);
		if (sessionKey == null) {
			this.sendAuthError(requestID);
		}
		
		byte[] encPayload = this.encrypt(sessionKey, payload);
		
		// append the hash of the cleartext to the end of the encrypted payload
		byte[] encPayloadWithOrigHash = new byte[encPayload.length + hashOrigPayload.length];
		System.arraycopy(encPayload, 0, encPayloadWithOrigHash, 0, encPayload.length);
		System.arraycopy(hashOrigPayload, 0, encPayloadWithOrigHash, encPayload.length, hashOrigPayload.length);

		this.sendCipherEncryptRESP(requestID, encPayloadWithOrigHash);
	}

	private void sendCipherEncryptRESP(int requestID, byte[] encPayloadWithOrigHash) throws Exception {
		//16-bit size
		int size = encPayloadWithOrigHash.length + 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_CIPHER_ENCRYPT_RESP.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//32-bit reserved field
		this.toOnion.write(new byte[4]);
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//write encrypted payload
		this.toOnion.write(encPayloadWithOrigHash);
		this.toOnion.flush();

	}

	public void handleCipherDecrypt(int size) throws Exception {
		//read 31-bit reserved field and 1-bit flag (which is ignored)
		byte[] reservedBytes = new byte[4];
		this.fromOnion.read(reservedBytes);

		//read 32-bit request ID
		byte[] requestIDBytes = new byte[4];
		int requestID = this.fromOnion.read(requestIDBytes, 0, 4);

		//read 16-bit session ID
		byte[] sessionIDBytes = new byte[3];
		this.fromOnion.read(sessionIDBytes, 0, 2);
		int sessionID = new BigInteger(sessionIDBytes).intValue();

		//get session key
		SecretKeySpec sessionKey = sessionKeyMap.get(sessionID);
		byte[] decPayload = null;
		byte[] payload = new byte[size - 14 - 32];
		this.fromOnion.read(payload, 0, payload.length);
		if (sessionKey == null) {
			this.sendAuthError(requestID);
		}

		// read hash value of original cleartext payload
		byte[] hashOrigPayload = new byte[32];
		this.fromOnion.read(hashOrigPayload, 0, hashOrigPayload.length);

		// if the decryption fails, send AUTH ERROR message instead
		try {
			decPayload = this.decrypt(sessionKey, payload);
		} catch (Exception e) {
			this.sendAuthError(requestID);
		}

		// append the hash of the cleartext to the end of the decrypted payload
		byte[] decPayloadWithOrigHash = new byte[decPayload.length + hashOrigPayload.length];
		System.arraycopy(decPayload, 0, decPayloadWithOrigHash, 0, decPayload.length);
		System.arraycopy(hashOrigPayload, 0, decPayloadWithOrigHash, decPayload.length, hashOrigPayload.length);

		this.sendCipherDecryptRESP(requestID, decPayloadWithOrigHash);
	}

	private void sendCipherDecryptRESP(int requestID, 
		byte[] decPayloadWithOrigHash) throws Exception {
		// Check if the decrypted payload matches the hash of the original cleartext payload
		byte[] decPayload = new byte[decPayloadWithOrigHash.length - 32];
		byte[] hashOrigPayload = new byte[32];
		System.arraycopy(decPayloadWithOrigHash, 0, decPayload, 0, decPayload.length);
		System.arraycopy(decPayloadWithOrigHash, decPayload.length, hashOrigPayload, 0, hashOrigPayload.length);
		byte[] hashDecPayload = this.hash(decPayload);
		boolean isHashMatch = Arrays.equals(hashDecPayload, hashOrigPayload);

		//16-bit size
		int size = decPayloadWithOrigHash.length + 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_CIPHER_DECRYPT_RESP.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//31-bit reserved field and 1-bit flag
		byte[] reserved = new byte[4];
		if (!isHashMatch) { // if hash does not match, then the payload is encrypted so set flag to 1
			reserved[3] = (byte)(reserved[3] | 1);
		}
		this.toOnion.write(reserved);
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();

		//write decrypted payload
		this.toOnion.write(decPayloadWithOrigHash);
		this.toOnion.flush();

	}


	public void handleSessionClose() throws Exception {
		// read 16-bit reserved field
		byte[] reservedBytes = new byte[2];
		this.fromOnion.read(reservedBytes);

		// read 16-bit session ID
		byte[] sessionIDBytes = new byte[3];
		this.fromOnion.read(sessionIDBytes, 0, 2);
		int sessionID = new BigInteger(sessionIDBytes).intValue();

		// remove corresponding session key from the hashmap
		this.sessionKeyMap.remove(sessionID);
	}

	//TODO
	private void sendAuthError(int requestID) throws Exception {
		//16-bit size
		int size = 12;
		byte[] sizeBytes = ByteBuffer.allocate(4).putInt(size).array();
		this.toOnion.write(Arrays.copyOfRange(sizeBytes, 2, 4));
		this.toOnion.flush();

		//16-bit message type
		byte[] typeBytes = ByteBuffer.allocate(4).putInt(
			MessageType.AUTH_ERROR.getVal()).array();
		this.toOnion.write(Arrays.copyOfRange(typeBytes, 2, 4));
		this.toOnion.flush();

		//32-bit reserved field
		this.toOnion.write(new byte[4]);
		this.toOnion.flush();

		//32-bit request ID
		byte[] requestIDBytes = ByteBuffer.allocate(4).putInt(requestID).array();
		this.toOnion.write(requestIDBytes);
		this.toOnion.flush();
	}


	// ========================================================================================
	//										HELPER METHODS	
	// ========================================================================================

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

	//encrypt with a random IV in GCM mode
	private byte[] encrypt(SecretKeySpec sessionKey, byte[] payload) throws Exception {
		//generate a random IV
		byte[] iv = new byte[12];
		new Random().nextBytes(iv);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
		byte[] ctxt = cipher.doFinal(payload);
		byte[] encPayload = new byte[iv.length + ctxt.length];
		System.arraycopy(iv, 0, encPayload, 0, iv.length);
		System.arraycopy(ctxt, 0, encPayload, iv.length, ctxt.length);
		//IV + ciphertext
		return encPayload;
	}

	//decrypt with a given IV in GCM mode
	private byte[] decrypt(SecretKeySpec sessionKey, byte[] payload) throws Exception {
		//read IV from payload
		byte[] iv = new byte[12];
		System.arraycopy(payload, 0, iv, 0, 12);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
		return cipher.doFinal(payload);	
	}

	//layer encrypt
	private byte[] layerEncrypt(ArrayList<SecretKeySpec> sessionKeys, byte[] payload) throws Exception {
		for (int i = 0; i < sessionKeys.size(); i++) {
			payload = this.encrypt(sessionKeys.get(i), payload);
		}
		return payload;
	}

	//layer decrypt
	private byte[] layerDecrypt(ArrayList<SecretKeySpec> sessionKeys, byte[] payload) throws Exception {
		for (int i = sessionKeys.size() - 1; i >= 0; i--) {
			payload = this.decrypt(sessionKeys.get(i), payload);
		}
		return payload;
	}

	// Hashes the payload using SHA-256
	private byte[] hash(byte[] payload) {
		this.sha256.update(payload);
		byte[] digest = this.sha256.digest();
		this.sha256.reset();

		return digest;
	}

}