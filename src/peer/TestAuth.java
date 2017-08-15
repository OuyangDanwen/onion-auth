import java.io.*;
import java.util.*;
import java.net.Socket;
import java.net.ServerSocket;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.*;
import javax.crypto.spec.*;
import javax.crypto.*;
import java.security.*;

public class TestAuth {

	public static void main(String[] args) {
		try {
			PeerOnionAuth auth = new PeerOnionAuth();

			if (args.length == 0) {
				auth.listenForConnection(9090);
			} else if (args.length == 1) {
				auth.listenForConnection(Integer.parseInt(args[0]));
			} else {
				System.out.println("Please use one of the following commands: java TestAuth, java TestAuth <portnum>");
				System.exit(0);
			}
		} catch (Exception e) {
			System.out.println(e.toString());
		}
	}
	
}