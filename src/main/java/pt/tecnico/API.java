package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.*;

import javax.crypto.Cipher;
import javax.swing.Action;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class API {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

	private static final int BUFFER_SIZE = 65507;
	private static final int SOCKET_TIMEOUT = 5000;
	private static final int ACCEPTED_INTERVAL = 5;

	private static int bankRequestID = Integer.MIN_VALUE;

	private static List<String> bankNames;
	private static List<Integer> bankPorts;

	private static int faults;

	//for each bank (String -> bank name)
	//it saves the current RequestId
	private static HashMap<String, Integer> bankRequestIdMap = new HashMap<>();

	API(List<String> bankNames, List<Integer> bankPorts, int faults){
		API.bankNames = bankNames;
		API.bankPorts = bankPorts;
		API.faults = faults;
	}

	public String setInitialRequestIDs(PrivateKey privateKey, int clientPort, int serverPort,
									   InetAddress serverAddress, PublicKey bankPublic, String username,
									   int requestID, String bankName)
			throws GeneralSecurityException, IOException {
		String[] response = new String[2];

		response[0] = sendMessageAndReceiveBody(privateKey, clientPort, serverPort, serverAddress, bankName, bankPublic,
				username, ActionLabel.REQUEST_MY_ID.getLabel(), requestID);

		response[1] = sendMessageAndReceiveBody(privateKey, clientPort, serverPort, serverAddress, bankName, bankPublic,
				username, ActionLabel.REQUEST_BANK_ID.getLabel(), requestID);

		if (!response[1].equals(ActionLabel.FAIL.getLabel())) {
			bankRequestID = Integer.parseInt(response[1]);
		}

		return response[0];
	}

	public String openAccount(PrivateKey accountPrivateKey, int clientPort,
							  int serverPort, InetAddress serverAddress,
							  PublicKey bankPublic, String username, int requestID, String bankName)
			throws GeneralSecurityException, IOException {

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverPort, serverAddress, bankName, bankPublic,
				username, ActionLabel.OPEN_ACCOUNT.getLabel(), requestID);
	}

	public String sendAmount(PrivateKey sourcePrivateKey, int clientPort,
							 int serverPort, InetAddress serverAddress, String bankName,
							 PublicKey bankPublic, int requestID, String username, float amount, String usernameDest)
			throws GeneralSecurityException, IOException {

		String bodyText = ActionLabel.SEND_AMOUNT.getLabel() + "," + amount + "," + usernameDest;

		return sendMessageAndReceiveBody(sourcePrivateKey, clientPort, serverPort, serverAddress, bankName, bankPublic, username, bodyText, requestID);
	}

	public String checkAccount(PrivateKey accountPrivateKey, int clientPort, int serverPort,
							   InetAddress serverAddress, String bankName,
							   PublicKey bankPublic, String username, int requestID, String owner)
			throws GeneralSecurityException, IOException {

		String bodyText = ActionLabel.CHECK_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverPort, serverAddress, bankName, bankPublic, username, bodyText, requestID);
	}

	public String receiveAmount(PrivateKey accountPrivateKey, int clientPort, int serverPort,
								InetAddress serverAddress, String bankName,
								PublicKey bankPublic, String username, int requestID, int transactionId)
			throws GeneralSecurityException, IOException {
		String bodyText = ActionLabel.RECEIVE_AMOUNT.getLabel() + "," + transactionId;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverPort, serverAddress, bankName, bankPublic, username, bodyText, requestID);
	}

	public String auditAccount(PrivateKey accountPrivateKey, int clientPort, int serverPort,
							   InetAddress serverAddress, String bankName,
							   PublicKey bankPublic, String username, int requestID, String owner)
			throws GeneralSecurityException, IOException {

		String bodyText = ActionLabel.AUDIT_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverPort, serverAddress, bankName, bankPublic, username, bodyText, requestID);
	}

	private String checkMessage(Cipher encryptCipher, String mac, MessageDigest msgDig, JsonObject infoJson,
								String requestIdBank, String bankName, String token, String requestID) {
		byte[] macBytes = null;
		try {
			macBytes = encryptCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			logger.error("Error: ", e);
			logger.info("Entity not authenticated!");
		}
		msgDig.update(infoJson.toString().getBytes());
		String result = ActionLabel.SUCCESS.getLabel();
		if (Arrays.equals(macBytes, msgDig.digest())) {
			logger.info("Confirmed equal body.");
		} else {
			logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes)));
			result = ActionLabel.FAIL.getLabel();
		}
		int idReceived = Integer.parseInt(requestIdBank);
		int currentBankRequestId;
		if (bankRequestIdMap.get(bankName) == null) {
			bankRequestIdMap.put(bankName, idReceived);
		} else {
			currentBankRequestId = bankRequestIdMap.get(bankName);
			if (idReceived <= currentBankRequestId) {
				logger.info("Message is duplicate, shall be ignored");
				result = ActionLabel.FAIL.getLabel();
			} else {
				bankRequestIdMap.replace(bankName, idReceived);
			}
		}
		if (Integer.parseInt(token) != Integer.parseInt(requestID)){
			logger.info("Message is duplicate, shall be ignored");
			result = ActionLabel.FAIL.getLabel();
		}

		return result;
	}

	private String sendMessageAndReceiveBody(PrivateKey accountPrivateKey, int clientPort,
											 int serverPort, InetAddress serverAddress, String bankName, PublicKey bankPublic, String username,
											 String bodyText, int requestID)
			throws GeneralSecurityException, IOException {
		String DIGEST_ALGO = "SHA-256";
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, accountPrivateKey);

		DatagramSocket socket = new DatagramSocket(clientPort);
		socket.setSoTimeout(SOCKET_TIMEOUT);
		// Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();

		JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
		infoJson.addProperty("to", bankName);
		infoJson.addProperty("from", username);
		infoJson.addProperty("body", bodyText);
		infoJson.addProperty("requestId", Integer.toString(requestID));

		requestJson.add("info", infoJson);

		msgDig.update(infoJson.toString().getBytes());
		String macString = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
		requestJson.addProperty("MAC", macString);

		logger.info("Request message: " + requestJson);

		// Send request
		byte[] clientData = requestJson.toString().getBytes();
		logger.info(String.format("%d bytes %n", clientData.length));
		DatagramPacket clientPacket = new DatagramPacket(clientData, clientData.length, serverAddress, serverPort);
		socket.send(clientPacket);
		logger.info(String.format("Request packet sent to %s:%d!%n", serverAddress, serverPort));

		// Receive response
		byte[] serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
		logger.info("Wait for response packet...");

		try {
			socket.receive(serverPacket);
		} catch (SocketTimeoutException e) {
			logger.info("Socket timeout. Failed request!");
			socket.close();
			logger.info("Socket closed");
			return ActionLabel.FAIL.getLabel();
		}

		// Convert response to string
		String serverText = new String(serverPacket.getData(), 0, serverPacket.getLength());
		logger.info("Received response: " + serverText);

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString(serverText).getAsJsonObject();
		JsonObject infoBankJson;
		String from, body, to, mac, requestIdBank, timestamp, token;

		infoBankJson = responseJson.getAsJsonObject("info");
		from = infoBankJson.get("from").getAsString();
		to = infoBankJson.get("to").getAsString();
		body = infoBankJson.get("body").getAsString();
		requestIdBank = infoBankJson.get("requestId").getAsString();
		token = infoBankJson.get("token").getAsString();

		mac = responseJson.get("MAC").getAsString();

		logger.info(String.format("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort()));
		logger.info(String.format("%d bytes %n", serverPacket.getLength()));

		encryptCipher.init(Cipher.DECRYPT_MODE, bankPublic);

		String messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, requestIdBank, from, token, Integer.toString(requestID));

		socket.close();
		logger.info("Socket closed");

		if (messageCheck.equals(ActionLabel.FAIL.getLabel())) {
			return messageCheck;
		} else {
			return body;
		}
	}


	// trying 
	private String sendMessageAndReceiveBody(PrivateKey accountPrivateKey, int clientPort,
											 InetAddress serverAddress, String username,
											 String bodyText, int requestID, String type)
			throws GeneralSecurityException, IOException {
		String DIGEST_ALGO = "SHA-256";
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, accountPrivateKey);

		String messageCheck;

		DatagramSocket socket = new DatagramSocket(clientPort);
		socket.setSoTimeout(SOCKET_TIMEOUT);
		
		// send request for all replicas
		for (int i = 0; i < bankPorts.size(); i++){
			// Create request message
			JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("to", bankNames.get(i));
			infoJson.addProperty("from", username);
			infoJson.addProperty("body", bodyText);
			infoJson.addProperty("requestId", Integer.toString(requestID));

			requestJson.add("info", infoJson);

			msgDig.update(infoJson.toString().getBytes());
			String macString = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
			requestJson.addProperty("MAC", macString);

			logger.info("Request message: " + requestJson);

			// Send request
			byte[] clientData = requestJson.toString().getBytes();
			logger.info(String.format("%d bytes %n", clientData.length));
			DatagramPacket clientPacket = new DatagramPacket(clientData, clientData.length, serverAddress, bankPorts.get(i));
			socket.send(clientPacket);
			logger.info(String.format("Request packet sent to %s:%d!%n", serverAddress, bankPorts.get(i)));

			socket.close();

		}

		int ackNumber = 0;
		int numberOfTries = 0;
		List<String> responseList = new ArrayList<>();
		List<Integer> idList = new ArrayList<>();
		boolean writeFinished = false;
		String writeFinalAnswer = null;
		boolean readFinished = false;
		List<Pair<String, String>> listPair = new ArrayList<Pair<String, String>>();
		// receive request based on type of operation
		while ( ( !writeFinished && type.equals(ActionLabel.WRITE.getLabel()) ) || ( !readFinished && type.equals(ActionLabel.WRITE.getLabel()) ) &&
				( ackNumber < bankPorts.size()            && type.equals(ActionLabel.OPEN_ACCOUNT.getLabel())  )  ||
				numberOfTries < bankPorts.size()){

			socket = new DatagramSocket(clientPort);
			socket.setSoTimeout(SOCKET_TIMEOUT);

			// Receive response
			byte[] serverData = new byte[BUFFER_SIZE];
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
			logger.info("Wait for response packet...");

			try {
				socket.receive(serverPacket);
			} catch (SocketTimeoutException e) {
				logger.info("Socket timeout. Failed request!");
				socket.close();
				logger.info("Socket closed");
				return ActionLabel.FAIL.getLabel();
			}

			logger.info(String.format("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort()));
			logger.info(String.format("%d bytes %n", serverPacket.getLength()));

			// Convert response to string
			String serverText = new String(serverPacket.getData(), 0, serverPacket.getLength());
			logger.info("Received response: " + serverText);

			// Parse JSON and extract arguments
			JsonObject responseJson = JsonParser.parseString(serverText).getAsJsonObject();
			JsonObject infoBankJson;
			String from, body, to, mac, requestIdBank, timestamp, token;

			infoBankJson = responseJson.getAsJsonObject("info");
			from = infoBankJson.get("from").getAsString();
			to = infoBankJson.get("to").getAsString();
			body = infoBankJson.get("body").getAsString();
			requestIdBank = infoBankJson.get("requestId").getAsString();
			token = infoBankJson.get("token").getAsString();

			mac = responseJson.get("MAC").getAsString();

			PublicKey bankPublicKey = readPublic("keys/" + from + "_public_key.der");

			encryptCipher.init(Cipher.DECRYPT_MODE, bankPublicKey);

			messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, requestIdBank, from, token, Integer.toString(requestID));
			if (!messageCheck.equals(ActionLabel.FAIL.getLabel())){
				responseList.add(messageCheck);

				if (type.equals(ActionLabel.WRITE.getLabel())){
					int occurrences = Collections.frequency(responseList, messageCheck);
					if (occurrences >= (bankPorts.size()+faults)/2){ // é preciso verificar se sao iguais
						writeFinished = true;
						writeFinalAnswer = messageCheck;
					}
					
				} else if (type.equals(ActionLabel.READ.getLabel())){
					ackNumber++;
					// add Pair (body, requestId) to dictionary
					if (ackNumber >= (bankPorts.size()+faults)/2){
						readFinished = true;
					}
				}
			}
			
			socket.close();
			logger.info("Socket closed");
			numberOfTries++;

		}

		if (type.equals(ActionLabel.WRITE.getLabel()) && writeFinished){
			return writeFinalAnswer;
		} else if (type.equals(ActionLabel.READ.getLabel()) && readFinished){
			return ActionLabel.TODO.getLabel();									// TODO escolher a resposta com o requestID mais alto
		} else if (type.equals(ActionLabel.OPEN_ACCOUNT.getLabel()) && responseList.size() == numberOfTries){
			return ActionLabel.ACCOUNT_CREATED.getLabel();
		} else {
			return ActionLabel.FAIL.getLabel();
		}
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
}