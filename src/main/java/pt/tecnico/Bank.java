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
	private static final int INITIAL_ACCOUNT_BALANCE = 1000;

	private static final String DIGEST_ALGO = "SHA-256";
	private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
	private static final String CLIENTS_CSV_FILE_PATH = "csv_files/clients.csv";
	private static final String REQUESTID_CSV_FILE_PATH = "csv_files/requestIDs.csv";


	private static String bankName;
	private static int transactionId = 0;
	private static int bankRequestId = 0;

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

	private static String getCurrentRequestIdFrom(String username) {

		FileReader fileReader;
		BufferedReader reader;
		String[] client;
		try {
			fileReader = new FileReader(REQUESTID_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				if (client[0].equals(username)) {
					return client[1];
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("openAccount: Error reading requestId file.");
		}
		return "-1";
	}

	private static void updateRequestID(String username, String requestID) {
		//get list of clients
		FileReader fileReader;
		BufferedReader reader;
		String[] client;
		List<String[]> clients = new ArrayList<>();
		try {
			fileReader = new FileReader(REQUESTID_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				clients.add(client);
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("openAccount: Error reading requestId file.");
		}

		for (String[] c : clients) {
			if (c[0].equals(username)) {
				c[1] = requestID;
				break;
			}
		}
		String path = "csv_files/requestIDs.csv";
		boolean flag = false;
		for (String[] c : clients) {
			writeToCSV(path, c, flag);
			flag = true;
		}
	}

	private static String setResponse(String[] bodyArray, String username) {
		//bodyArray -> 1-amount, 2-receiver
		if (bodyArray[0].equals(ActionLabel.OPEN_ACCOUNT.getLabel())) {
			return handleOpenAccount(username);
		} else if (bodyArray[0].equals(ActionLabel.SEND_AMOUNT.getLabel())) {
			return handleSendAmountRequest(username, bodyArray[1], bodyArray[2]);
		} else if (bodyArray[0].equals(ActionLabel.CHECK_ACCOUNT.getLabel())) {
			return handleCheckAccountRequest(bodyArray[1]);
		} else if (bodyArray[0].equals(ActionLabel.RECEIVE_AMOUNT.getLabel())) {
			return handleReceiveAmountRequest(username, bodyArray[1]);
		} else if (bodyArray[0].equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {
			return handleAuditAccountRequest(bodyArray[1]);
		} else if (bodyArray[0].equals(ActionLabel.REQUEST_MY_ID.getLabel())) {
			return getCurrentRequestIdFrom(username);
		} else if (bodyArray[0].equals(ActionLabel.REQUEST_BANK_ID.getLabel())) {
			return String.valueOf(bankRequestId);
		} else {
			return ActionLabel.UNKNOWN_FUNCTION.getLabel();
		}
	}

	private static String handleOpenAccount(String username) {
		FileReader fileReader;
		BufferedReader reader;
		String[] client;
		try {
			fileReader = new FileReader(CLIENTS_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				if (client[0].equals(username)) {
					return ActionLabel.DUPLICATE_USERNAME.getLabel();
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("openAccount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		writeToCSV(CLIENTS_CSV_FILE_PATH, new String[]{username, Integer.toString(INITIAL_ACCOUNT_BALANCE),
				Integer.toString(INITIAL_ACCOUNT_BALANCE)}, true);
		createTransactionHistoryFiles(username);

		writeToCSV(REQUESTID_CSV_FILE_PATH, new String[]{username, Integer.toString(0)}, true);

		return ActionLabel.ACCOUNT_CREATED.getLabel();
	}

	private static String handleAuditAccountRequest(String owner) {
		FileReader fileReader;
		BufferedReader reader;
		String[] client = null;
		try {
			fileReader = new FileReader(CLIENTS_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				if (client[0].equals(owner)) {
					break;
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("auditAccount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		if (client == null) {
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		} else {
			StringBuilder response = new StringBuilder();
			for (int i = 0; i < client.length; i++) {
				String s = client[i];
				response.append(s);
				if (i != client.length - 1) { //last one doesn't need ","
					response.append(",");
				}
			}
			String ownerPendingTransactionsPath = "csv_files/" + owner + "_complete_transaction_history.csv";
			try {
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
				logger.info("auditAccount: Error reading complete transactions file.");
				return ActionLabel.FAIL.getLabel();
			}
		}
	}

	private static String handleCheckAccountRequest(String owner) {
		FileReader fileReader;
		BufferedReader reader;
		String[] client = null;
		try {
			fileReader = new FileReader(CLIENTS_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				if (client[0].equals(owner)) {
					break;
				}
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			logger.info("checkAccount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		if (client == null) {
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		} else {
			StringBuilder response = new StringBuilder();
			for (int i = 0; i < client.length; i++) {
				String s = client[i];
				response.append(s);
				if (i != client.length - 1) { //last one doesn't need ","
					response.append(",");
				}
			}
			String ownerPendingTransactionsPath = "csv_files/" + owner + "_pending_transaction_history.csv";
			try {
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

	private static String handleSendAmountRequest(String username, String amount, String receiver) {
		//get account information
		String[] client;
		List<String[]> clients = new ArrayList<>();
		FileReader fileReader;
		BufferedReader reader;
		try {
			fileReader = new FileReader(CLIENTS_CSV_FILE_PATH);
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
		for (String[] c : clients) {
			System.out.print("c[0]:");
			System.out.println("|" + c[0] + "|");
			if (c[0].equals(username)) {
				//c -> 0-username, 1-available amount, 2-book
				//check negative amount
				if (Float.parseFloat(amount) < 0) {
					return ActionLabel.NEGATIVE_AMOUNT.getLabel();
				}
				//check available amount
				float final_amount = Float.parseFloat(c[1]) - Float.parseFloat(amount);
				if (final_amount >= 0) {
					c[1] = String.valueOf(final_amount);
				} else {
					return ActionLabel.INSUFFICIENT_AMOUNT.getLabel();
				}
				senderFound = true;
			} else if (c[0].equals(receiver)) {
				receiverFound = true;
			}
		}

		if (receiverFound && senderFound) {
			//this boolean is used to overwrite file. First call to write overwrites files and following call just append
			boolean flag = false;
			for (String[] c : clients) {
				writeToCSV(CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
				flag = true;
			}

			String receiverPendingTransactionsFile = "csv_files/" + receiver + "_pending_transaction_history.csv";
			String senderPendingTransactionsFile = "csv_files/" + username + "_pending_transaction_history.csv";

			String[] transaction = new String[5];
			transaction[0] = String.valueOf(transactionId);
			transaction[1] = new Timestamp(System.currentTimeMillis()).toString();
			transaction[2] = username;
			transaction[3] = receiver;
			transaction[4] = amount;

			transactionId++;

			writeToCSV(receiverPendingTransactionsFile, transaction, true);
			writeToCSV(senderPendingTransactionsFile, transaction, true);

			return ActionLabel.PENDING_TRANSACTION.getLabel();
		} else {
			logger.info("sendAmount: Sender/Receiver client not found or trying to send money to self!");
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		}
	}

	private static String handleReceiveAmountRequest(String username, String id) {
		//get account information
		String[] client;
		List<String[]> clients = new ArrayList<>();
		FileReader fileReader;
		BufferedReader reader;
		try {
			fileReader = new FileReader(CLIENTS_CSV_FILE_PATH);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				client = line.split(",");
				clients.add(client);
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			System.out.println("sendAmount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}


		boolean usernameFound = false;
		for (String[] c : clients) {
			System.out.print("c[0]:");
			System.out.println("|" + c[0] + "|");
			if (c[0].equals(username)) {
				//c -> 0-username, 1-available amount, 2-book
				usernameFound = true;
			}
		}

		String[] pendingTransaction;
		String usernamePendingTransactionsPath = "csv_files/" + username + "_pending_transaction_history.csv";
		List<String[]> pendingTransactions = new ArrayList<>();
		try {
			fileReader = new FileReader(usernamePendingTransactionsPath);
			reader = new BufferedReader(fileReader);
			String line;
			while ((line = reader.readLine()) != null) {
				pendingTransaction = line.split(",");
				pendingTransactions.add(pendingTransaction);
			}
			fileReader.close();
			reader.close();
		} catch (IOException e) {
			System.out.println("sendAmount: Error reading clients file.");
			return ActionLabel.FAIL.getLabel();
		}

		String sender = null;
		boolean transactionFound = false;
		boolean receiverFound = false;
		boolean senderFound = false;
		String[] receiverTransaction = null;
		for (String[] t : pendingTransactions) {
			System.out.print("c[0]:");
			System.out.println("|" + t[0] + "|");
			if (t[0].equals(id)) {
				//c -> 0-id, 1-timestamp, 2-sender 3-receiver 4-amount
				//check if client is receiver
				if (t[3].equals(username)) {
					transactionFound = true;
					for (String[] c : clients) {
						System.out.print("c[0]:");
						System.out.println("|" + c[0] + "|");
						if (c[0].equals(username)) {
							//c -> 0-username, 1-available amount, 2-book
							receiverFound = true;
							float available_final_amount = Float.parseFloat(c[1]) + Float.parseFloat(t[4]);
							float book_final_amount = Float.parseFloat(c[1]) + Float.parseFloat(t[4]);
							c[1] = String.valueOf(available_final_amount);
							c[2] = String.valueOf(book_final_amount);
						} else if (c[0].equals(t[2])) {
							senderFound = true;
							sender = c[0];
							float final_amount = Float.parseFloat(c[2]) - Float.parseFloat(t[4]);
							c[2] = String.valueOf(final_amount);
						}
					}
					receiverTransaction = t;
				} else {
					return ActionLabel.CLIENT_NOT_RECEIVER.getLabel();
				}

			}
		}

		if (usernameFound && transactionFound && senderFound && receiverFound) {
			//this boolean is used to overwrite file. First call to write overwrites files and following call just append
			boolean flag = false;
			for (String[] c : clients) {
				writeToCSV(CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
				flag = true;
			}

			// updating transactions in 
			String[] pendingTransactionSender;
			String usernamePendingTransactionsSenderPath = "csv_files/" + sender + "_pending_transaction_history.csv";
			List<String[]> pendingTransactionsSender = new ArrayList<>();
			String[] transactionInSender = null;
			try {
				fileReader = new FileReader(usernamePendingTransactionsSenderPath);
				reader = new BufferedReader(fileReader);
				String line;
				while ((line = reader.readLine()) != null) {
					pendingTransactionSender = line.split(",");
					if (pendingTransactionSender[0].equals(id)) {
						transactionInSender = pendingTransactionSender;
					}
					pendingTransactionsSender.add(pendingTransactionSender);

				}
				fileReader.close();
				reader.close();
			} catch (IOException e) {
				System.out.println("sendAmount: Error reading clients file.");
				return ActionLabel.FAIL.getLabel();
			}

			pendingTransactions.remove(receiverTransaction);
			pendingTransactionsSender.remove(transactionInSender);

			String receiverPendingTransactionsFile = "csv_files/" + username + "_pending_transaction_history.csv";
			String receiverTransactionsFile = "csv_files/" + username + "_complete_transaction_history.csv";
			String senderPendingTransactionsFile = "csv_files/" + sender + "_pending_transaction_history.csv";
			String senderCompletedTransactionsFile = "csv_files/" + sender + "_complete_transaction_history.csv";

			System.out.println("Receiver pending " + pendingTransactions.size() + "; sender pending " + pendingTransactionsSender.size());
			System.out.println("");
			System.out.println("");
			System.out.println("");
			System.out.println("");

			if (pendingTransactions.size() == 0) {
				// clear all contents of file
				try {
					File pendingTransactionHistoryFile = new File("csv_files/" + username + "_pending_transaction_history.csv");
					pendingTransactionHistoryFile.delete();
					pendingTransactionHistoryFile.createNewFile();
				} catch (IOException e) {
					System.out.println("sendAmount: Error reading clients file.");
					return ActionLabel.FAIL.getLabel();
				}
			} else {
				flag = false;
				for (String[] t : pendingTransactions) {
					writeToCSV(receiverPendingTransactionsFile, t, flag); //rewrite pending transaction of receiver file
					flag = true;
				}
			}

			if (pendingTransactionsSender.size() == 0) {
				// clear all contents of file
				try {
					File pendingTransactionHistoryFile = new File("csv_files/" + sender + "_pending_transaction_history.csv");
					pendingTransactionHistoryFile.delete();
					pendingTransactionHistoryFile.createNewFile();
				} catch (IOException e) {
					System.out.println("sendAmount: Error reading clients file.");
					return ActionLabel.FAIL.getLabel();
				}
			} else {
				flag = false;
				for (String[] t : pendingTransactionsSender) {
					writeToCSV(senderPendingTransactionsFile, t, flag); //rewrite pending transaction of sender  file
					flag = true;
				}
			}

			writeToCSV(receiverTransactionsFile, receiverTransaction, true);
			writeToCSV(senderCompletedTransactionsFile, receiverTransaction, true);

			return ActionLabel.COMPLETED_TRANSACTION.getLabel();
		} else {
			System.out.println("sendAmount: Sender/Receiver client not found!");
			return ActionLabel.CLIENT_NOT_FOUND.getLabel();
		}

	}

	private static void createTransactionHistoryFiles(String username) {
		File completeTransactionHistoryFile = new File("csv_files/" + username + "_complete_transaction_history.csv");
		File pendingTransactionHistoryFile = new File("csv_files/" + username + "_pending_transaction_history.csv");
		if (!completeTransactionHistoryFile.exists()) {
			try {
				completeTransactionHistoryFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		if (!pendingTransactionHistoryFile.exists()) {
			try {
				pendingTransactionHistoryFile.createNewFile();
			} catch (IOException e) {
				logger.error("Error: ", e);
			}
		}
		try {
			completeTransactionHistoryFile.createNewFile();
			pendingTransactionHistoryFile.createNewFile();
		} catch (IOException e) {
			logger.error("Error: ", e);
		}
	}

	public static void main(String[] args) {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			return;
		}
		final int port = Integer.parseInt(args[0]);
		bankName = args[1];
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

				// Convert request to string
				String clientText = new String(clientData, 0, clientLength);
				logger.info("Received request: " + clientText);

				String[] response = receiveMessageAndCheckSafety(clientText);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();

				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("from", bankName);
				infoJson.addProperty("to", response[1]);
				infoJson.addProperty("requestId", Integer.toString(bankRequestId));
				infoJson.addProperty("body", response[0]);

				bankRequestId++;

				responseJson.add("info", infoJson);

				if (decryptCipher != null && msgDig != null) {
					decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
					msgDig.update(infoJson.toString().getBytes());
					String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
					responseJson.addProperty("MAC", ins);
					//Store signature
					writeToCSV("csv_files/signatures.csv", new String[]{bankName, response[1], ins}, true);
				}

				logger.info("Response message: " + responseJson);

				// Send response
				byte[] serverData = responseJson.toString().getBytes();
				logger.info(String.format("%d bytes %n", serverData.length));
				DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientPacket.getAddress(), clientPacket.getPort());
				socket.send(serverPacket);
				logger.info(String.format("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort()));
			} catch (IOException | GeneralSecurityException e) {
				logger.error("Error: ", e);
			}
		}
	}

	public static String[] receiveMessageAndCheckSafety(String clientText) throws GeneralSecurityException, IOException {
		String[] response = new String[2];

		PrivateKey privKey = readPrivate("keys/bank_private_key.der");
		PublicKey pubClientKey;
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);
		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

		// Parse JSON and extract arguments
		JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
		String from, body, to, mac, requestId;

		JsonObject infoClientJson = requestJson.getAsJsonObject("info");
		to = infoClientJson.get("to").getAsString();
		from = infoClientJson.get("from").getAsString();
		body = infoClientJson.get("body").getAsString();
		requestId = infoClientJson.get("requestId").getAsString();
		mac = requestJson.get("MAC").getAsString();

		String[] bodyArray = body.split(",");

		response[0] = ActionLabel.FAIL.getLabel();
		String publicClientPath = "keys/" + from + "_public_key.der";
		pubClientKey = readPublic(publicClientPath);
		decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
		signCipher.init(Cipher.DECRYPT_MODE, pubClientKey);

		int idReceived = Integer.parseInt(requestId);

		int currentId = Integer.parseInt(getCurrentRequestIdFrom(from));

		if (idReceived <= currentId) {
			logger.info("Message is duplicate, shall be ignored");
			response[0] = ActionLabel.FAIL.getLabel();
		} else if (currentId == -1) {
			logger.error("Client has no request ID");
			response[0] = ActionLabel.FAIL.getLabel();
		} else if (idReceived != Integer.MAX_VALUE) { //valid request id
			updateRequestID(from, requestId);
		}

		byte[] macBytes;
		try {
			macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			logger.error("Error: ", e);
			logger.info("Entity not authenticated!");
			return response;
		}
		msgDig.update(infoClientJson.toString().getBytes());
		if (Arrays.equals(macBytes, msgDig.digest())) {
			logger.info("Confirmed content integrity.");
		} else {
			logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes)));
			return response;
		}

		//Store signature
		writeToCSV("csv_files/signatures.csv", new String[]{from, bankName, mac}, true);

		response[0] = setResponse(bodyArray, from);
		response[1] = from;

		logger.info(String.format("Message to '%s', from '%s':%n%s%n", to, from, body));
		logger.info("response body = " + response[0]);

		return response;
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
		} catch (IOException e) {
			logger.error("Error: ", e);
		}
	}
}