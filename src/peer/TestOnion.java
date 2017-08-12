import java.io.*;
import java.util.*;
import java.net.Socket;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.nio.ByteBuffer;
import java.security.spec.*;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.security.*;

class TestOnion {
	private DataOutputStream to;
	private DataInputStream from;


	public static void main(String[] args) {
		TestOnion onion = new TestOnion();
		try {

			Socket skt = new Socket("127.0.0.1", 9090);
			onion.to = new DataOutputStream(skt.getOutputStream());
			onion.from = new DataInputStream(skt.getInputStream());
			onion.sendAuthStart();

      	} catch (Exception e) {
      		System.out.println(e.toString());
      	}

	}

	private void sendAuthStart() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(4096);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey rsaPub = keyPair.getPublic();
		byte[] encodedPub = rsaPub.getEncoded();
		System.out.println("rsa public key size: " + encodedPub.length);

		byte[] messageType = new byte[2];
		byte[] reserved = new byte[4];
		byte[] requestID = new byte[4];

		int size = 2 + 2 + 4 + 4 + encodedPub.length;
		byte[] sizeBytes = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(size).array(), 2, 4);
		System.out.println("total size is: " + new BigInteger(sizeBytes).intValue());

		this.to.write(sizeBytes);
		this.to.flush();
		this.to.write(messageType);
		this.to.flush();
		this.to.write(reserved);
		this.to.flush();
		this.to.write(requestID);
		this.to.flush();
		this.to.write(encodedPub);
		//this.to.flush();
		//this.to.write(Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(10000).array(), 2, 4));
	}

	//encrypt with a random IV in GCM mode
	public byte[] encrypt(SecretKey aesKey, byte[] payload, byte[] iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
		return cipher.doFinal(payload);
	}

	public byte[] decrypt(SecretKey aesKey, byte[] payload, byte[] iv) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
		return cipher.doFinal(payload);	
	}
	
}