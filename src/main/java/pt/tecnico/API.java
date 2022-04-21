package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.security.PublicKey;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class API {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

	private static final int BUFFER_SIZE = 65507;
	private static final int SOCKET_TIMEOUT = 5000;
	private static final int ACCEPTED_INTERVAL = 5;

	private static int bankRequestID = Integer.MIN_VALUE;

	//for each bank (String -> bank name)
	//it saves the current RequestId
	private static HashMap<String, Integer> bankRequestIdMap = new HashMap<>();

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

		logger.info(String.format("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort()));
		logger.info(String.format("%d bytes %n", serverPacket.getLength()));

		encryptCipher.init(Cipher.DECRYPT_MODE, bankPublic);

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

		String messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, requestIdBank, from, token, Integer.toString(requestID));

		socket.close();
		logger.info("Socket closed");

		if (messageCheck.equals(ActionLabel.FAIL.getLabel())) {
			return messageCheck;
		} else {
			return body;
		}
	}
}