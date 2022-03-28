package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Hashtable;
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

	private static final int INITIAL_ACCOUNT_BALANCE = 1000;

	private static final String DIGEST_ALGO = "SHA-256";
	private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

	private static Hashtable<String, Integer> requestIds = new Hashtable<String, Integer>();

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

	public static IvParameterSpec generateIv() {
		byte[] initVec = new byte[16];
		new SecureRandom().nextBytes(initVec);
		return new IvParameterSpec(initVec);
	}

	private static String setResponse(String[] bodyArray, String username) {

		if(bodyArray[0].equals(ActionLabel.OPEN_ACCOUNT.getLabel())) {
			writeToCSV("csv_files/clients.csv", new String[]{username, Integer.toString(INITIAL_ACCOUNT_BALANCE),
					Integer.toString(INITIAL_ACCOUNT_BALANCE)}, true);
			createTransactionHistoryFiles(username);
			return ActionLabel.ACCOUNT_CREATED.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.SEND_AMOUNT.getLabel())) { // 1 - amount, 2 - receiver

			String amount = bodyArray[1];
			String receiver = bodyArray[2];

			return handleSendAmountRequest(username, amount, receiver);

		} else if(bodyArray[0].equals(ActionLabel.CHECK_ACCOUNT.getLabel())) {
			return handleCheckAccountRequest(bodyArray[1]);
		} else if(bodyArray[0].equals(ActionLabel.RECEIVE_AMOUNT.getLabel())) {
			return ActionLabel.TODO.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {
			return ActionLabel.TODO.getLabel();
		} else {
			return ActionLabel.UNKNOWN_FUNCTION.getLabel();
		}
	}

	private static String handleCheckAccountRequest(String owner){

		String clientsFilePath = "csv_files/clients.csv";
		List<String[]> clients = new ArrayList<>();
		FileReader fileReader;
		BufferedReader reader;
		String[] client = null;
		try {
			fileReader = new FileReader(clientsFilePath);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				if(client[0].equals(owner)){
					break;
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("checkAccount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		if(client == null){
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		} else {
			StringBuilder response = new StringBuilder();
			for(int i = 0; i < client.length; i++){
				String s = client[i];
				response.append(s);
				if(i != client.length - 1) { //last one doesn't need ","
					response.append(",");
				}
			}
			String ownerPendingTransactionsPath = "csv_files/" + owner + "_pending_transaction_history.csv";
			try{
				fileReader = new FileReader(ownerPendingTransactionsPath);
				reader = new BufferedReader(fileReader);
				String line;

				while ((line = reader.readLine()) != null) { //transactions separated with ";"
					response.append(";");
					response.append(line);
				}
				fileReader.close();
				reader.close();

				return response.toString();
			} catch (IOException e) {
				logger.info("checkAccount: Error reading pending transactions file.");
				return ActionLabel.FAIL.getLabel();
			}
		}
	}

	private static String handleSendAmountRequest(String username, String amount, String receiver){
		//get account information
		String[] client = null;

		String clientsFilePath = "csv_files/clients.csv";
		List<String[]> clients = new ArrayList<>();
		FileReader fileReader;
		BufferedReader reader;
		try {
			fileReader = new FileReader(clientsFilePath);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				clients.add(client);
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("sendAmount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		boolean senderFound = false;
		boolean receiverFound = false;
		for(String[] c: clients){
			System.out.print("c[0]:");
			System.out.println("|" + c[0] + "|");
			if(c[0].equals(username)){
				//c -> 0-username, 1-available amount, 2-book
				//check available amount
				float final_amount = Float.parseFloat(c[1]) - Float.parseFloat(amount);
				if(final_amount >= 0){
					c[1] = String.valueOf(final_amount);
					senderFound = true;
				} else {
					return ActionLabel.INSUFFICIENT_AMOUNT.getLabel();
				}
			} else if(c[0].equals(receiver)){
				receiverFound = true;
			}
		}

		if(receiverFound && senderFound){
			//this boolean is used to overwrite file. First call to write overwrites files and following call just append
			boolean flag = false;
			for(String[] c: clients){
				writeToCSV(clientsFilePath,c,flag); //rewrite clients file
				flag = true;
			}

			String receiverPendingTransactionsFile = "csv_files/" + receiver + "_pending_transaction_history.csv";
			String senderPendingTransactionsFile = "csv_files/" + username + "_pending_transaction_history.csv";

			String[] transaction = new String[4];
			transaction[0] = new Timestamp(System.currentTimeMillis()).toString();
			transaction[1] = username;
			transaction[2] = receiver;
			transaction[3] = amount;

			writeToCSV(receiverPendingTransactionsFile,transaction,true);
			writeToCSV(senderPendingTransactionsFile,transaction,true);

			return ActionLabel.PENDING_TRANSACTION.getLabel();
		} else {
			logger.info("sendAmount: Sender/Receiver client not found!");
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		}
	}

	private static void createTransactionHistoryFiles(String username) {
		File completeTransactionHistoryFile = new File("csv_files/" + username + "_complete_transaction_history.csv");
		File pendingTransactionHistoryFile = new File("csv_files/" + username + "_pending_transaction_history.csv");
		if(!completeTransactionHistoryFile.exists()) {
			try {
				completeTransactionHistoryFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error", e);
			}
		}
		if(!pendingTransactionHistoryFile.exists()) {
			try {
				pendingTransactionHistoryFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error", e);
			}
		}
		try {
			completeTransactionHistoryFile.createNewFile();
			pendingTransactionHistoryFile.createNewFile();
		} catch (IOException e) {
			logger.error("Error", e);
		}
	}

	public static void main(String[] args) throws Exception {
		// Check arguments
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			return;
		}
		final int port = Integer.parseInt(args[0]);
		Instant inst;

		// Hash and (de)cipher algorithms initialization
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);

		PublicKey pubKey = readPublic("keys/bank_public_key.der");
		PrivateKey privKey = readPrivate("keys/bank_private_key.der");
		PublicKey pubClientKey = null; //readPublic("keys/pis_public_key.der");

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

		// Create server socket
		logger.info(String.format("Server will receive packets on port %d %n", port));
		
		// Wait for client packets 
		while (true) {
			try (DatagramSocket socket = new DatagramSocket(port)) {

				byte[] buf = new byte[BUFFER_SIZE];
				// Receive packet
				DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
				socket.receive(clientPacket);
				InetAddress clientAddress = clientPacket.getAddress();
				int clientPort = clientPacket.getPort();
				int clientLength = clientPacket.getLength();
				byte[] clientData = clientPacket.getData();
				logger.info(String.format("Received request packet from %s:%d!%n", clientAddress, clientPort));
				logger.info(String.format("%d bytes %n", clientLength));

				inst = Instant.now();

				// Convert request to string
				String clientText = new String(clientData, 0, clientLength);
				logger.info("Received request: " + clientText);

				String[] response = receiveMessageAndCheckSafety(clientText);

				decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
				inst = Instant.now().plus(15, ChronoUnit.MINUTES);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();

				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("from", "BFTB");
				infoJson.addProperty("to", response[1]);
				infoJson.addProperty("instant", inst.toString());
				infoJson.addProperty("body", response[0]);

				responseJson.add("info", infoJson);

				msgDig.update(infoJson.toString().getBytes());
				String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
				responseJson.addProperty("MAC", ins);

				logger.info("Response message: " + responseJson);

				// Send response
				byte[] serverData = responseJson.toString().getBytes();
				logger.info(String.format("%d bytes %n", serverData.length));
				DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientPacket.getAddress(), clientPacket.getPort());
				socket.send(serverPacket);
				logger.info(String.format("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort()));
			}
		}
	}

	private static void writeToCSV(String filePath, String[] values, boolean append) {
		try {
			FileWriter outputFile = new FileWriter(filePath, append);
			CSVWriter writer = new CSVWriter(outputFile, ',',
					CSVWriter.NO_QUOTE_CHARACTER,
					CSVWriter.DEFAULT_ESCAPE_CHARACTER,
					CSVWriter.DEFAULT_LINE_END);
			writer.writeNext(values);
			writer.close();
		}
		catch (IOException e) {
			logger.error("Error", e);
		}
	}

	private static String[] receiveMessageAndCheckSafety(String clientText) throws GeneralSecurityException, IOException {
		String[] response = new String[2];

		PublicKey pubKey = readPublic("keys/bank_public_key.der");
		PrivateKey privKey = readPrivate("keys/bank_private_key.der");
		PublicKey pubClientKey = null;
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);
		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

		// Parse JSON and extract arguments
		JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
		String from, body, to, mac, client, instant, token, keyString;

		JsonObject infoClientJson = requestJson.getAsJsonObject("info");
		to = infoClientJson.get("to").getAsString();
		from = infoClientJson.get("from").getAsString();
		body = infoClientJson.get("body").getAsString();
		instant = infoClientJson.get("instant").getAsString();
		mac = requestJson.get("MAC").getAsString();

		String[] bodyArray = body.split(",");

		response[0] = ActionLabel.FAIL.getLabel();
		String publicClientPath = "keys/" + from + "_public_key.der";
		pubClientKey = readPublic(publicClientPath);
		decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
		signCipher.init(Cipher.DECRYPT_MODE, pubClientKey);

		int idReceived = Integer.parseInt(instant);
		if (requestIds.get(from) == null){
			requestIds.put(from, idReceived);
		} else if (Integer.compare(idReceived, requestIds.get(from)) <= 0 ){
			logger.info("Message is duplicate, shall be ignored");
			response[0] = ActionLabel.SUCCESS.getLabel();
		}

		byte[] macBytes = null;
		try {
			macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			logger.error("Error", e);
			logger.info("Entity not authenticated!");
			return response;
		}
		msgDig.update(infoClientJson.toString().getBytes());
		if (Arrays.equals(macBytes, msgDig.digest())) {
			logger.info("Confirmed content integrity.");
		} else {
			logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes))); // TODO ignore execution of message
			return response;
		}

		response[0] = setResponse(bodyArray, from);
		response[1] = from;

		logger.info(String.format("Message to '%s', from '%s':%n%s%n", to, from, body));
		logger.info("response body = " + response[0]);

		return response;
	}
}