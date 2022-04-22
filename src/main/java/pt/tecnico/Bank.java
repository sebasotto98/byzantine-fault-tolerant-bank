package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.opencsv.CSVWriter;

public class Bank {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However, the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header).
	 */
	private static final int BUFFER_SIZE = (64 * 1024 - 1) - 8 - 20;
	private static final int SHORT_REQUEST_INTERVAL = 500;
	private static final int MIN_INGRESS_DATA_LENGTH = 10;
	private static final int MAX_CLIENT_LOAD = BUFFER_SIZE * 10;
	private static final int RECENT_REQUESTS_STORED = 10;

	private static final String DIGEST_ALGO = "SHA-256";
	private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

	private static final SharedBankVars bankVars = new SharedBankVars();
	private static final Map<String, Instant> recentRequestAddressTimes = new HashMap<>();
	private static final Map<String, List<Integer>> recentRequestAddressLengths = new HashMap<>();

	//configVars
	private static final String BANK_CONFIG_FILE = "config_files/banks.txt";
	private static int port;
	private static int initialThreadPort;
	private static int numberOfThreads;
	private static String bankName;

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
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			return;
		}
		bankName = args[0];

		readConfig();
		createCommonHistoryFiles();

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
				socket.setReceiveBufferSize(BUFFER_SIZE * 10); //10 packet buffer
				// Receive packet
				DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
				socket.receive(clientPacket);

				if( //isSimultaneousRequest(clientPacket) ||
					isLowIngressDataLengthRequest(clientPacket) ||
					isHighRecentLoadRequest(clientPacket)) {
					continue;
				}

				//thread ends automatically
				threads[currentThreadIndex] = new WorkerThread(currentThreadPort, clientPacket, bankName, decryptCipher, msgDig, privKey, bankVars);
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

	private static boolean isHighRecentLoadRequest(DatagramPacket clientPacket) {
		String requestAddress = clientPacket.getAddress().getHostAddress();
		int requestLength = clientPacket.getLength();
		int load = 0;
		if(recentRequestAddressLengths.containsKey(requestAddress)) {
			for(int length : recentRequestAddressLengths.get(requestAddress)) {
				load += length;
			}
			if(load > MAX_CLIENT_LOAD) {
				logger.info("Request denied! High recent load from client with IP address: " + requestAddress);
				return true;
			}
		}
		if(recentRequestAddressLengths.size() > RECENT_REQUESTS_STORED) {
			recentRequestAddressLengths.remove(recentRequestAddressLengths.keySet().stream().findFirst().get());
		}
		if(!recentRequestAddressLengths.containsKey(requestAddress)) {
			recentRequestAddressLengths.put(requestAddress, new ArrayList<>());
		}
		recentRequestAddressLengths.get(requestAddress).add(requestLength);

		return false;
	}

	private static boolean isLowIngressDataLengthRequest(DatagramPacket clientPacket) {
		String requestAddress = clientPacket.getAddress().getHostAddress();
		int requestLength = clientPacket.getLength();
		if(requestLength < MIN_INGRESS_DATA_LENGTH) {
			logger.info("Request denied! Low ingress data length in request from client with IP address: " + requestAddress);
			return true;
		}
		return false;
	}

	private static boolean isSimultaneousRequest(DatagramPacket clientPacket) {
		String requestAddress = clientPacket.getAddress().getHostAddress();
		Instant now = Instant.now();
		if(recentRequestAddressTimes.containsKey(requestAddress)) {
			if(Duration.between(recentRequestAddressTimes.get(requestAddress), now).toMillis() < SHORT_REQUEST_INTERVAL) {
				logger.info("Request denied! Two or more requests in a short interval from client with IP address: " + requestAddress);
				return true;
			}
		}
		if(recentRequestAddressTimes.size() > RECENT_REQUESTS_STORED) {
			recentRequestAddressTimes.remove(recentRequestAddressTimes.keySet().stream().findFirst().get());
		}
		recentRequestAddressTimes.put(requestAddress, now);
		return false;
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
				//bank only needs this bank information
				if(infos[0].equals(bankName)){
					port = Integer.parseInt(infos[1]);
					initialThreadPort = Integer.parseInt(infos[2]);
					numberOfThreads = Integer.parseInt(infos[3]);
					break;
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("Error reading read config file.");
		}
	}

	private static void createCommonHistoryFiles() {
		File replicaFolder = new File(bankName + "_csv_files");
		File clientsFile = new File(bankName + "_csv_files/clients.csv");
		File requestIdsFile = new File(bankName + "_csv_files/requestIDs.csv");
		File signaturesFile = new File(bankName + "_csv_files/signatures.csv");
		File transactionIdFile = new File(bankName + "_csv_files/transactionId.csv");
		File completedSignSignatures = new File(bankName + "_csv_files/completedSignedTransactions.csv");
		File pendingSignSignatures = new File(bankName + "_csv_files/pendingSignedTransactions.csv");

		if (!replicaFolder.exists()) {
			replicaFolder.mkdirs();
		}
		if (!clientsFile.exists()) {
			try {
				clientsFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!requestIdsFile.exists()) {
			try {
				requestIdsFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!signaturesFile.exists()) {
			try {
				signaturesFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!transactionIdFile.exists()) {
			try {
				transactionIdFile.createNewFile();
				FileWriter outputFile = new FileWriter(bankName + "_csv_files/transactionId.csv", false);
				CSVWriter writer = new CSVWriter(outputFile, ',',
						CSVWriter.NO_QUOTE_CHARACTER,
						CSVWriter.DEFAULT_ESCAPE_CHARACTER,
						CSVWriter.DEFAULT_LINE_END);
				writer.writeNext(new String[]{Integer.toString(0)});
				writer.close();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!completedSignSignatures.exists()) {
			try {
				requestIdsFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!pendingSignSignatures.exists()) {
			try {
				requestIdsFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
    }
}