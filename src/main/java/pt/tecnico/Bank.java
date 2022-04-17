package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opencsv.CSVWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;

public class Bank {



	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However, the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header).
	 */
	private static final int BUFFER_SIZE = (64 * 1024 - 1) - 8 - 20;

	private static final String DIGEST_ALGO = "SHA-256";
	private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

	private static final SharedBankVars bankVars = new SharedBankVars();

	//configVars
	private static final String BANK_CONFIG_FILE = "config_files/banks.txt";
	private static int port;
	private static int initialThreadPort;
	private static int numberOfThreads;
	private static String bankName;
	private static int replicas;
	private static int faults;

	private static List<String> bankNames = new ArrayList<>();
	private static List<Integer> bankPorts = new ArrayList<>();

	public static KeyPair read(String publicKeyPath, String privateKeyPath) throws GeneralSecurityException, IOException {
		logger.info("Reading public key from file " + publicKeyPath + " ...");
		FileInputStream pubFis = new FileInputStream(publicKeyPath);
		byte[] pubEncoded = new byte[pubFis.available()];
		pubFis.read(pubEncoded);
		pubFis.close();

		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
		KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
		PublicKey pub = keyFacPub.generatePublic(pubSpec);

		logger.info("Reading private key from file " + privateKeyPath + " ...");
		FileInputStream privFis = new FileInputStream(privateKeyPath);
		byte[] privEncoded = new byte[privFis.available()];
		privFis.read(privEncoded);
		privFis.close();

		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
		KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
		PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

		KeyPair keys = new KeyPair(pub, priv);
		return keys;
	}

	public static PublicKey readPublic(String publicKeyPath) throws GeneralSecurityException, IOException {
		logger.info("Reading public key from file " + publicKeyPath + " ...");
		FileInputStream pubFis = new FileInputStream(publicKeyPath);
		byte[] pubEncoded = new byte[pubFis.available()];
		pubFis.read(pubEncoded);
		pubFis.close();

		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
		KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
		PublicKey pub = keyFacPub.generatePublic(pubSpec);

		return pub;
	}

	public static PrivateKey readPrivate(String privateKeyPath) throws GeneralSecurityException, IOException {
		logger.info("Reading private key from file " + privateKeyPath + " ...");
		FileInputStream privFis = new FileInputStream(privateKeyPath);
		byte[] privEncoded = new byte[privFis.available()];
		privFis.read(privEncoded);
		privFis.close();

		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
		KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
		PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

		return priv;
	}

	public static void main(String[] args) {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing!");
			return;
		}
		bankName = args[0];
		replicas = Integer.parseInt(args[1]);
		faults = Integer.parseInt(args[2]);
		readConfig();

		int currentThreadIndex = 0;
		int currentThreadPort = initialThreadPort;
		Thread[] threads = new Thread[numberOfThreads];

		MessageDigest msgDig = null;
		Cipher decryptCipher = null;
		PrivateKey privKey = null;

		try {
			// Hash and (de)cipher algorithms initialization
			msgDig = MessageDigest.getInstance(DIGEST_ALGO);
			decryptCipher = Cipher.getInstance(CIPHER_ALGO);

			privKey = readPrivate("keys/" + bankName + "_private_key.der");

		} catch (GeneralSecurityException | IOException e) {
			logger.error("Error: ", e);
		}
		// Create server socket
		logger.info(String.format("Server will receive packets on port %d %n", port));

		// Wait for client packets
		while (true) {
			try (DatagramSocket socket = new DatagramSocket(port)) {
				byte[] buf = new byte[BUFFER_SIZE];
				// Receive packet
				DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
				socket.receive(clientPacket);

				//thread ends automatically
				threads[currentThreadIndex] = new WorkerThread(currentThreadPort, clientPacket, logger, bankName, decryptCipher, msgDig, privKey, bankVars);
				threads[currentThreadIndex].start();

				currentThreadIndex++;
				currentThreadIndex = currentThreadIndex % numberOfThreads;

				currentThreadPort++;
				if(currentThreadPort >= initialThreadPort + numberOfThreads){
					currentThreadPort = initialThreadPort;
				}
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
	}

	private static void readConfig(){
		FileReader fileReader;
		BufferedReader reader;
		String[] infos;
		try {
			fileReader = new FileReader(BANK_CONFIG_FILE);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				infos = line.split(",");
				if(infos[0].equals(bankName)){
					port = Integer.parseInt(infos[1]);
					initialThreadPort = Integer.parseInt(infos[2]);
					numberOfThreads = Integer.parseInt(infos[3]);
				} else {
					bankNames.add(infos[0]);
					bankPorts.add(Integer.parseInt(infos[1]));
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("openAccount: Error reading requestId file.");
		}
	}
}