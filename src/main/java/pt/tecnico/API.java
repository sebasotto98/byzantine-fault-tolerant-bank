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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class API {

	private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

    private static final int BUFFER_SIZE = 65507;
    private static final int SOCKET_TIMEOUT = 5;

	public String openAccount(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort,
                            int serverPort, InetAddress serverAddress, PublicKey bankPublic, String username, int requestID)
                            throws GeneralSecurityException, IOException  {

        String body = sendMessageAndReceiveBody(accountPublicKey, accountPrivateKey, clientPort, serverPort, serverAddress, bankPublic,
				username, ActionLabel.OPEN_ACCOUNT.getLabel(), requestID);
		
		if (body.equals(ActionLabel.ACCOUNT_CREATED.getLabel())) {
            return ActionLabel.SUCCESS.getLabel();
        } else {
            return ActionLabel.FAIL.getLabel();
        }
    }

    public String sendAmount(PublicKey sourcePublicKey, PrivateKey sourcePrivateKey, PublicKey destPublicKey, int clientPort,
						   int serverPort, InetAddress serverAddress, PublicKey bankPublic, int requestID, String username, float amount, String usernameDest)
			throws GeneralSecurityException, IOException {

    	String bodyText = ActionLabel.SEND_AMOUNT.getLabel() + "," + amount + "," + usernameDest;

		return sendMessageAndReceiveBody(sourcePublicKey, sourcePrivateKey, clientPort, serverPort, serverAddress, bankPublic, username, bodyText, requestID);
    }

    public String checkAccount(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort, int serverPort,
							   InetAddress serverAddress, PublicKey bankPublic, String username, int requestID, String owner, PublicKey ownerKey)
			throws GeneralSecurityException, IOException {

    	String bodyText = ActionLabel.CHECK_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPublicKey, accountPrivateKey, clientPort, serverPort, serverAddress, bankPublic, username, bodyText, requestID);
    }

    public String receiveAmount(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort, int serverPort,
								InetAddress serverAddress, PublicKey bankPublic, String username, int requestID, int transactionId)
							throws GeneralSecurityException, IOException  {
		String bodyText = ActionLabel.RECEIVE_AMOUNT.getLabel() + "," + transactionId;

		return sendMessageAndReceiveBody(accountPublicKey, accountPrivateKey, clientPort, serverPort, serverAddress, bankPublic, username, bodyText, requestID);
    }

    public String auditAccount(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort, int serverPort,
					  InetAddress serverAddress, PublicKey bankPublic, String username, int requestID, String owner, PublicKey ownerKey)
			throws GeneralSecurityException, IOException {

		String bodyText = ActionLabel.AUDIT_ACCOUNT.getLabel() + "," + owner;

		return sendMessageAndReceiveBody(accountPublicKey, accountPrivateKey, clientPort, serverPort, serverAddress, bankPublic, username, bodyText, requestID);
	}

    private String checkMessage(Cipher encryptCipher, String mac, MessageDigest msgDig, JsonObject infoJson,
                            String instantBank, Instant inst) {
        byte[] macBytes = null;
		try {
			macBytes = encryptCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			logger.error("Error", e);
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
		if (inst.compareTo(Instant.parse(instantBank)) > 0) {
			logger.info("Old message resent!");
			result = ActionLabel.FAIL.getLabel();
		} else {
			logger.info("Confirmed message freshness.");
		}
        return result;
    }

	private String sendMessageAndReceiveBody(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort,
											int serverPort, InetAddress serverAddress, PublicKey bankPublic, String username, 
											String bodyText, int requestID) 
											throws GeneralSecurityException, IOException  {
		
		// Timestamps are in UTC
		Instant inst = Instant.now().plus(SOCKET_TIMEOUT, ChronoUnit.MINUTES);

		String DIGEST_ALGO = "SHA-256";
		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, accountPrivateKey);

		// Create socket
		DatagramSocket socket = new DatagramSocket(clientPort);
		socket.setSoTimeout(SOCKET_TIMEOUT*1000);
        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		
        JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
        infoJson.addProperty("to", "BFTB");
		infoJson.addProperty("from", username);

        infoJson.addProperty("body", bodyText);
        infoJson.addProperty("instant", Integer.toString(requestID));

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
			// Close socket
			socket.close();
			logger.info("Socket closed");
			return ActionLabel.FAIL.getLabel();
		}

		logger.info(String.format("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort()));
		logger.info(String.format("%d bytes %n", serverPacket.getLength()));

		inst = Instant.now();
		encryptCipher.init(Cipher.DECRYPT_MODE, bankPublic);

		// Convert response to string
		String serverText = new String(serverPacket.getData(), 0, serverPacket.getLength());
		logger.info("Received response: " + serverText);

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString(serverText).getAsJsonObject();
        JsonObject infoBankJson;
		String from, body, to, mac, instantBank;
		
        infoBankJson = responseJson.getAsJsonObject("info");
        from = infoBankJson.get("from").getAsString();
        to = infoBankJson.get("to").getAsString();
        body = infoBankJson.get("body").getAsString();
        instantBank = infoBankJson.get("instant").getAsString();
        
        mac = responseJson.get("MAC").getAsString();
		
        String messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, instantBank, inst);

		socket.close();
		logger.info("Socket closed");

		if (messageCheck.equals(ActionLabel.FAIL.getLabel())) {
			return ActionLabel.FAIL.getLabel();
		} else{
			return body;
		}
    }
}