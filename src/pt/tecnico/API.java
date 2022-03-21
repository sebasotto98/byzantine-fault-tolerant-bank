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
	private final String ASYM_ALGO = "RSA/ECB/PKCS1Padding";

    public int openAccount(PublicKey accountPublickey, PrivateKey accountPrivatekey, int clientPort, int clientId,
                            int serverPort, InetAddress serverAddress, PublicKey bankPublic) 
                            throws GeneralSecurityException, IOException  {

        // Timestamps are in UTC
		Instant inst = Instant.now().plus(SOCKET_TIMEOUT, ChronoUnit.MINUTES);
		
		//final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		//KeyPair keys = read("keys/pis_public_key.der","keys/pis_private_key.der");

		//PublicKey bankPublic = readPublic("keys/bank_public_key.der");
		Cipher encryptCipher = Cipher.getInstance(ASYM_ALGO);
		//encryptCipher.init(Cipher.ENCRYPT_MODE, bankPublic);

		//Cipher symCipher = Cipher.getInstance(SYM_ALGO);
		//SecretKey symKey = generateSessionKey();
		//IvParameterSpec iv = generateIv();
		//symCipher.init(Cipher.ENCRYPT_MODE, symKey, iv);

		Cipher signCipher = Cipher.getInstance(ASYM_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, accountPrivatekey);

		// Concat IV and session key to send
		//ByteArrayOutputStream outputStream = new ByteArrayOutputStream(symKey.getEncoded().length + iv.getIV().length);
		//outputStream.write(symKey.getEncoded());
		//outputStream.write(iv.getIV());

		// Create socket
		DatagramSocket socket = new DatagramSocket(clientPort);
        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		
        JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
        infoJson.addProperty("client", clientId);
        infoJson.addProperty("to", "BFTB");

        String bodyText = "OpenAccount";
        //byte[] cipheredBody = symCipher.doFinal(bodyText.getBytes());
        //String bodyEnc = Base64.getEncoder().encodeToString(cipheredBody);
        infoJson.addProperty("body", bodyText);
        infoJson.addProperty("instant", inst.toString());

        requestJson.addProperty("infoJson", infoJson.toString());

        msgDig.update(infoJson.getAsByte());
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
		
        int messageCheck = checkMessage(encryptCipher, mac, msgDig, infoJson, instantBank, inst);
		//String bodyDec = new String(symCipher.doFinal(Base64.getDecoder().decode(body)));
		// Close socket
		socket.close();
		System.out.println("Socket closed");
		
		if (messageCheck == CORRECT && body.equals("AccountCreated")) {

			writeToCSV("csv_files/clients.csv", new String[]{accountPublickey.toString(), "1000", "1000"});

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
                            String instantBank, Instant inst){
        byte[] macBytes = null;
		try {
			macBytes = encryptCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			System.out.println("Entity not authenticated!");
		}
		msgDig.update(infoJson.getAsByte());
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

	public static void writeToCSV(String filePath, String[] values) {
		File file = new File(filePath);
		try {
			FileWriter outputFile = new FileWriter(file);
			CSVWriter writer = new CSVWriter(outputFile);
			writer.writeNext(values);
			writer.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}
