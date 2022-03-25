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
import com.opencsv.CSVWriter;

public class API {

    private static final int BUFFER_SIZE = 65507;
    public static final int FAIL = 2;
    public static final int CORRECT = 1;
    private static final int SOCKET_TIMEOUT = 5;
    private final String DIGEST_ALGO = "SHA-256";
	private final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

    public int openAccount(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort,
                            int serverPort, InetAddress serverAddress, PublicKey bankPublic, String username)
                            throws GeneralSecurityException, IOException {

        String body = sendMessageAndReceiveBody(accountPublicKey, accountPrivateKey, clientPort, serverPort, serverAddress, bankPublic, username, "OpenAccount");
		
		if (body.equals("AccountCreated")) {
            return CORRECT;
        } else {
            return FAIL;
        }

    }

    public void sendAmount(PublicKey source, PublicKey dest, float amount) {

    }

    public void checkAccount(PublicKey key) {

    }

    public void receiveAmount(PublicKey key) {

    }

    public void audit(PublicKey key) {

    }

    private int checkMessage(Cipher encryptCipher, String mac, MessageDigest msgDig, JsonObject infoJson,
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
            return FAIL;
        } else {
            return CORRECT;
        }
    }

	private String sendMessageAndReceiveBody(PublicKey accountPublicKey, PrivateKey accountPrivateKey, int clientPort,
											int serverPort, InetAddress serverAddress, PublicKey bankPublic, String username, String bodyText) 
											throws GeneralSecurityException, IOException {
		
		// Timestamps are in UTC
		Instant inst = Instant.now().plus(SOCKET_TIMEOUT, ChronoUnit.MINUTES);

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
        infoJson.addProperty("instant", inst.toString());

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
		
        int messageCheck = checkMessage(encryptCipher, mac, msgDig, infoBankJson, instantBank, inst);

		// Close socket
		socket.close();
		System.out.println("Socket closed");

		if (messageCheck == CORRECT) {
			return body;
		} else{
			return "Failed";
		}
    }


}
