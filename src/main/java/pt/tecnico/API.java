package pt.tecnico;

import java.io.*;
import java.security.PublicKey;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
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

public class API {

    private static final int BUFFER_SIZE = 65507;
    private static final int SOCKET_TIMEOUT = 5;
    private final String DIGEST_ALGO = "SHA-256";
	private final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

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

    public void checkAccount(PublicKey key) {

    }

    public void receiveAmount(PublicKey key) {

    }

    public void audit(PublicKey key) {

    }

    private String checkMessage(Cipher encryptCipher, String mac, MessageDigest msgDig, JsonObject infoJson,
                            String instantBank, Instant inst) {
        byte[] macBytes = null;
		try {
			macBytes = encryptCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Entity not authenticated!");
		}
		msgDig.update(infoJson.toString().getBytes());
		String result = "accepted";
		if (Arrays.equals(macBytes, msgDig.digest())) {
			System.out.println("Confirmed equal body.");
		} else {
			System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes));	
			result = "failed";
		}
		if (inst.compareTo(Instant.parse(instantBank)) > 0) {
			System.out.println("Old message resent!");
			result = "failed";
		} else {
			System.out.println("Confirmed message freshness.");
		}
        if (result.equals("failed")) {
            return ActionLabel.FAIL.getLabel();
        } else {
            return ActionLabel.SUCCESS.getLabel();
        }
    }

	private String sendMessageAndReceiveBody(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort,
											int serverPort, InetAddress serverAddress, PublicKey bankPublic, String username, 
											String bodyText, int requestID) 
											throws GeneralSecurityException, IOException  {
		
		// Timestamps are in UTC
		Instant inst = Instant.now().plus(SOCKET_TIMEOUT, ChronoUnit.MINUTES);
		
		//final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, accountPrivateKey);

		// Create socket
		DatagramSocket socket = new DatagramSocket(clientPort);
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
		
		System.out.println("Request message: " + requestJson);
		
		// Send request
		byte[] clientData = requestJson.toString().getBytes();
		System.out.printf("%d bytes %n", clientData.length);
		DatagramPacket clientPacket = new DatagramPacket(clientData, clientData.length, serverAddress, serverPort);
		socket.send(clientPacket);
		System.out.printf("Request packet sent to %s:%d!%n", serverAddress, serverPort);

		// Receive response
		byte[] serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
		System.out.println("Wait for response packet...");
		socket.receive(serverPacket);
		System.out.printf("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort());
		System.out.printf("%d bytes %n", serverPacket.getLength());

		inst = Instant.now();
		//symCipher.init(Cipher.DECRYPT_MODE, symKey, iv);
		encryptCipher.init(Cipher.DECRYPT_MODE, bankPublic);

		// Convert response to string
		String serverText = new String(serverPacket.getData(), 0, serverPacket.getLength());
		System.out.println("Received response: " + serverText);

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

		// Close socket
		socket.close();
		System.out.println("Socket closed");

		if (messageCheck.equals(ActionLabel.SUCCESS.getLabel())) {
			return body;
		} else{
			return "Failed";
		}
    }


}
