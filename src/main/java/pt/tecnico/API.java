package pt.tecnico;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.*;
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

	private static int bankRequestID = Integer.MIN_VALUE;

	private static boolean auditing = false;
	private static boolean checking = false;

	private static List<String> bankNames;
	private static List<Integer> bankPorts;

	private static int faults;

	//for each bank (String -> bank name)
	//it saves the current RequestId
	private static HashMap<String, Integer> bankRequestIdMap = new HashMap<>();

	API(List<String> bankNames, List<Integer> bankPorts, int faults) {
		API.bankNames = bankNames;
		API.bankPorts = bankPorts;
		API.faults = faults;
	}

	public String setInitialRequestIDs(PrivateKey privateKey, int clientPort, InetAddress serverAddress,
									   String username, int requestID)
			throws GeneralSecurityException, IOException {

		return sendMessageAndReceiveBody(privateKey, clientPort, serverAddress,
				username, ActionLabel.REQUEST_MY_ID.getLabel(), requestID, ActionLabel.REQUEST_MY_ID.getLabel());
	}

	public String openAccount(PrivateKey accountPrivateKey, int clientPort, InetAddress serverAddress,
							  String username, int requestID)
			throws GeneralSecurityException, IOException {

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverAddress,
				username, ActionLabel.OPEN_ACCOUNT.getLabel(), requestID, ActionLabel.OPEN_ACCOUNT.getLabel());
	}

	public String sendAmount(PrivateKey sourcePrivateKey, int clientPort, InetAddress serverAddress,
							 int requestID, String username, float amount, String usernameDest)
			throws GeneralSecurityException, IOException {

		String bodyText = ActionLabel.SEND_AMOUNT.getLabel() + "," + amount + "," + usernameDest;

		return sendMessageAndReceiveBody(sourcePrivateKey, clientPort, serverAddress, username, bodyText, requestID, ActionLabel.WRITE.getLabel());
	}

	public String checkAccount(PrivateKey accountPrivateKey, int clientPort, InetAddress serverAddress,
							   String username, int requestID, String owner)
			throws GeneralSecurityException, IOException {

		checking = true;
		String bodyText = ActionLabel.CHECK_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverAddress, username, bodyText, requestID, ActionLabel.READ.getLabel());
	}

	public String receiveAmount(PrivateKey accountPrivateKey, int clientPort, InetAddress serverAddress,
								String username, int requestID, int transactionId)
			throws GeneralSecurityException, IOException {


		String bodyText = ActionLabel.RECEIVE_AMOUNT.getLabel() + "," + transactionId;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverAddress, username, bodyText, requestID, ActionLabel.WRITE.getLabel());
	}

	public String auditAccount(PrivateKey accountPrivateKey, int clientPort, InetAddress serverAddress,
							   String username, int requestID, String owner)
			throws GeneralSecurityException, IOException {

		auditing = true;
		String bodyText = ActionLabel.AUDIT_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverAddress, username, bodyText, requestID, ActionLabel.READ.getLabel());
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
		if (Integer.parseInt(token) != Integer.parseInt(requestID)) {
			logger.info("Message is duplicate, shall be ignored");
			result = ActionLabel.FAIL.getLabel();
		}

		return result;
	}

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
		socket.setReceiveBufferSize(BUFFER_SIZE * 10); //10 packets in the buffer
		// send request for all replicas
		for (int i = 0; i < bankPorts.size(); i++) {

			// Create request message
			JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("to", bankNames.get(i));
			infoJson.addProperty("from", username);
			infoJson.addProperty("body", bodyText);
			infoJson.addProperty("requestId", Integer.toString(requestID));

			String verificationString = bankNames.get(i) + "," + username + "," + requestID + "," + bodyText;
			msgDig.update(verificationString.getBytes());
			String signature = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
			infoJson.addProperty("signature", signature);

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
		}

		int ackNumber = 0;
		int numberOfTries = 0;
		List<String> responseList = new ArrayList<>();
		List<String> openAccountResponseList = new ArrayList<>();
		List<Integer> idList = new ArrayList<>();
		boolean writeFinished = false;
		String writeFinalAnswer = null;
		boolean readFinished = false;
		HashMap<Integer, String> valueID = new HashMap<>();
		String operation = bodyText.split(",")[0];
		int maxId = -1;
		int maxIdBank = -1;
		// receive request based on type of operation
		while (((!writeFinished && type.equals(ActionLabel.WRITE.getLabel())) ||
				(!readFinished && type.equals(ActionLabel.READ.getLabel())) ||
				(type.equals(ActionLabel.OPEN_ACCOUNT.getLabel()) || type.equals(ActionLabel.REQUEST_MY_ID.getLabel())))
				&& numberOfTries < bankPorts.size()) {

			// Receive response
			byte[] serverData = new byte[BUFFER_SIZE];
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
			logger.info("Wait for response packet...");
			socket.setSoTimeout(SOCKET_TIMEOUT);
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
			//to = infoBankJson.get("to").getAsString();
			body = infoBankJson.get("body").getAsString();
			requestIdBank = infoBankJson.get("requestId").getAsString();
			token = infoBankJson.get("token").getAsString();

			mac = responseJson.get("MAC").getAsString();

			PublicKey bankPublicKey = readPublic("keys/" + from + "_public_key.der");

			encryptCipher.init(Cipher.DECRYPT_MODE, bankPublicKey);

			messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, requestIdBank, from, token, Integer.toString(requestID));
			if (!messageCheck.equals(ActionLabel.FAIL.getLabel())) {
				responseList.add(messageCheck);

				if (type.equals(ActionLabel.WRITE.getLabel())) {
					int occurrences = Collections.frequency(responseList, messageCheck);
					if (occurrences >= (bankPorts.size() + faults) / 2) { // é preciso verificar se sao iguais
						writeFinished = true;
						writeFinalAnswer = messageCheck;
					}

				} else if (type.equals(ActionLabel.READ.getLabel())) {
					logger.info("bodyText = " + body);
					String userBeingSeen = body.split(",")[0];
					logger.info("user with key = " + body.split(",")[0]);
					int numberOfSignatures = checkSignatures(body, operation, userBeingSeen);
					logger.info("number of signatures = " + numberOfSignatures);
					if (numberOfSignatures != -1) {
						ackNumber++;
						valueID.put(numberOfSignatures, body);
					}
					if (ackNumber >= (bankPorts.size() + faults) / 2) {
						readFinished = true;
					}
				} else if (type.equals(ActionLabel.REQUEST_MY_ID.getLabel())) {
					String[] ids = body.split(",");
					if (!ids[0].equals(ActionLabel.FAIL.getLabel()) && Integer.parseInt(ids[0]) > maxId) {
						maxId = Integer.parseInt(ids[0]);
					}
					if (!ids[1].equals(ActionLabel.FAIL.getLabel()) && Integer.parseInt(ids[1]) > maxIdBank) {
						maxIdBank = Integer.parseInt(ids[1]);
					}
				}
			}
			if (type.equals(ActionLabel.OPEN_ACCOUNT.getLabel())) {
				openAccountResponseList.add(body);
			}
			numberOfTries++;
		}
		logger.info("Socket closed");
		socket.close();

		if (type.equals(ActionLabel.WRITE.getLabel()) && writeFinished) {
			return writeFinalAnswer;
		} else if (type.equals(ActionLabel.READ.getLabel()) && readFinished) {
			Integer key = Collections.max(valueID.keySet());
			String writeBack = ActionLabel.WRITE_BACK.getLabel() + ",";
			if (auditing) {
				writeBack = writeBack + ActionLabel.AUDITING.getLabel() + ";";
				auditing = false;
			} else if (checking) {
				writeBack = writeBack + ActionLabel.CHECKING.getLabel() + ";";
				checking = false;
			}
			writeBack = writeBack + valueID.get(key);
			sendMessageAndReceiveBody(accountPrivateKey, clientPort, serverAddress, username, writeBack, requestID + 1, ActionLabel.WRITE.getLabel());

			return valueID.get(key);
		} else if (type.equals(ActionLabel.OPEN_ACCOUNT.getLabel()) && responseList.size() == numberOfTries) {
			if (Collections.frequency(openAccountResponseList, ActionLabel.DUPLICATE_USERNAME.getLabel()) > faults) {
				return ActionLabel.DUPLICATE_USERNAME.getLabel();
			} else if (Collections.frequency(openAccountResponseList, ActionLabel.FAIL.getLabel()) > faults) {
				return ActionLabel.FAIL.getLabel();
			} else {
				return ActionLabel.ACCOUNT_CREATED.getLabel();
			}
		} else if (type.equals(ActionLabel.REQUEST_MY_ID.getLabel()) && responseList.size() == numberOfTries) {
			bankRequestID = maxIdBank;
			if (maxId == -1) {
				return ActionLabel.FAIL.getLabel();
			}
			return Integer.toString(maxId);
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

	private boolean checkSignatureInfo(String transactionString, String type, String userWithTransaction)
			throws GeneralSecurityException, IOException {
		logger.info("transactionString = " + transactionString);
		String[] splited = transactionString.split(",");

		String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		int size = splited.length;

		if (type.equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {

			PublicKey usernameKey = readPublic("keys/" + userWithTransaction + "_public_key.der");
			encryptCipher.init(Cipher.DECRYPT_MODE, usernameKey);

			try {
				Base64.getEncoder().encodeToString(encryptCipher.doFinal(Base64.getDecoder().decode(splited[size - 1])));
			} catch (Exception e) {
				logger.info("Signature does not match!");
				return false;
			}
		} else {
			PublicKey usernameKey = readPublic("keys/" + splited[2] + "_public_key.der");
			encryptCipher.init(Cipher.DECRYPT_MODE, usernameKey);

			try {
				Base64.getEncoder().encodeToString(encryptCipher.doFinal(Base64.getDecoder().decode(splited[size - 1])));
			} catch (Exception e) {
				logger.info("Signature does not match!");
				return false;
			}
		}
		return true;
	}

	private int checkSignatures(String transactions, String type, String username)
			throws GeneralSecurityException, IOException {
		String[] transactionsList = transactions.split(";");
		int result = 0;
		for (int i = 1; i < transactionsList.length; i++) {
			if (checkSignatureInfo(transactionsList[i], type, username)) {
				result++;
			} else {
				return -1;
			}
		}
		return result;
	}
}