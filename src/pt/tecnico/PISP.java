package pt.tecnico;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class PISP {

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = 65_507;
	private static final int AES_SIZE = 256;

	public static KeyPair read(String publicKeyPath, String privateKeyPath) throws GeneralSecurityException, IOException {
        System.out.println("Reading public key from file " + publicKeyPath + " ...");
        FileInputStream pubFis = new FileInputStream(publicKeyPath);
        byte[] pubEncoded = new byte[pubFis.available()];
        pubFis.read(pubEncoded);
        pubFis.close();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);

        System.out.println("Reading private key from file " + privateKeyPath + " ...");
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
		System.out.println("Reading public key from file " + publicKeyPath + " ...");
        FileInputStream pubFis = new FileInputStream(publicKeyPath);
        byte[] pubEncoded = new byte[pubFis.available()];
        pubFis.read(pubEncoded);
        pubFis.close();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);

		return pub;
	}

	public static SecretKey generateSessionKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(AES_SIZE);
		return keyGen.generateKey();
	}

	public static IvParameterSpec generateIv() {
		byte[] initVec = new byte[16];
		new SecureRandom().nextBytes(initVec);
		return new IvParameterSpec(initVec);
	}

	public static int paymentService(String serverHost, InetAddress serverAddress, int serverPort, 
								String accountNumber, String client, String amount, int pisPort)
								throws GeneralSecurityException, IOException {
		// Timestamps are in UTC
		Instant inst = Instant.now().plus(15, ChronoUnit.MINUTES);

		// Hash and cipher algorithms initialization
		final String DIGEST_ALGO = "SHA-256";
		final String ASYM_ALGO = "RSA/ECB/PKCS1Padding";
		final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		KeyPair keys = read("keys/pis_public_key.der","keys/pis_private_key.der");

		PublicKey bankPublic = readPublic("keys/bank_public_key.der");
		Cipher encryptCipher = Cipher.getInstance(ASYM_ALGO);
		encryptCipher.init(Cipher.ENCRYPT_MODE, bankPublic);

		Cipher symCipher = Cipher.getInstance(SYM_ALGO);
		SecretKey symKey = generateSessionKey();
		IvParameterSpec iv = generateIv();
		symCipher.init(Cipher.ENCRYPT_MODE, symKey, iv);

		Cipher signCipher = Cipher.getInstance(ASYM_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());

		// Concat IV and session key to send
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(symKey.getEncoded().length + iv.getIV().length);
		outputStream.write(symKey.getEncoded());
		outputStream.write(iv.getIV());

		// Create socket
		DatagramSocket socket = new DatagramSocket(pisPort + 1);
        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("from", "PIS");
			String clientString = Base64.getEncoder().encodeToString(symCipher.doFinal(client.getBytes()));
			infoJson.addProperty("client", clientString);
			infoJson.addProperty("to", "BankEntity");
			requestJson.add("info", infoJson);

			String bodyText = accountNumber + "," + amount;
			byte[] cipheredBody = symCipher.doFinal(bodyText.getBytes());
			String bodyEnc = Base64.getEncoder().encodeToString(cipheredBody);
			requestJson.addProperty("body", bodyEnc);

			msgDig.update(cipheredBody);
			String macString = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
			requestJson.addProperty("MAC", macString);
			String token = Base64.getEncoder().encodeToString(encryptCipher.doFinal(inst.toString().getBytes()));
			requestJson.addProperty("token", token);
			String keyString = Base64.getEncoder().encodeToString(encryptCipher.doFinal(outputStream.toByteArray()));
			requestJson.addProperty("SessionKey", keyString);	
		}
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
		symCipher.init(Cipher.DECRYPT_MODE, symKey, iv);
		encryptCipher.init(Cipher.DECRYPT_MODE, bankPublic);

		// Convert response to string
		String serverText = new String(serverPacket.getData(), 0, serverPacket.getLength());
		System.out.println("Received response: " + serverText);

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString(serverText).getAsJsonObject();
		String from, body, to, mac, token;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
			from = infoJson.get("from").getAsString();
			to = infoJson.get("to").getAsString();
			body = responseJson.get("body").getAsString();
			mac = responseJson.get("MAC").getAsString();
			token = responseJson.get("Token").getAsString();
		}
		
		byte[] macBytes = null;
		try {
			macBytes = encryptCipher.doFinal(Base64.getDecoder().decode(mac));
		} catch (Exception e) {
			System.out.println("Entity not authenticated!");
		}
		msgDig.update(Base64.getDecoder().decode(body));
		String result = "accepted";
		if (Arrays.equals(macBytes, msgDig.digest())) {
			System.out.println("Confirmed equal body.");
		} else {
			System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes));	
			result = "failed";
		}

		String tok = new String(symCipher.doFinal(Base64.getDecoder().decode(token)));
		if (inst.compareTo(Instant.parse(tok)) > 0) {
			System.out.println("Old message resent!");
			result = "failed";
		} else {
			System.out.println("Confirmed message freshness.");
		}

		String bodyDec = new String(symCipher.doFinal(Base64.getDecoder().decode(body)));
		// Close socket
		socket.close();
		System.out.println("Socket closed");
		
		if (bodyDec.equals("failed")){
			result = "failed";
		}

		if (result.equals("accepted")){
			return 0;
		} else {
			return 1;
		}
	}


	public static void main(String[] args) throws Exception {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing!");
			//System.err.printf("Usage: java %s host port%n", JsonClient.class.getName());
			return;
		}
		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);

		final int PISport = Integer.parseInt(args[2]);

		final String ivBackString = "1234567890123456";
		byte[] keyBackend = new byte[32];

		IvParameterSpec ivBackend = new IvParameterSpec(ivBackString.getBytes());

		// Hash and (de)cipher algorithms initialization
		final String DIGEST_ALGO = "SHA-256";
		final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest djangoMsgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher djangoDecryptCipher = Cipher.getInstance(CIPHER_ALGO);
		Cipher pisDecryptCipher = Cipher.getInstance(CIPHER_ALGO);
		KeyPair keys = read("keys/pis_public_key.der", "keys/pis_private_key.der");

		PublicKey djangoKey = readPublic("keys/django_public_key.der");
		djangoDecryptCipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());

		Cipher djangoSymCipher = Cipher.getInstance(SYM_ALGO);

		Cipher djangoEncryptCipher = Cipher.getInstance(CIPHER_ALGO);
		djangoEncryptCipher.init(Cipher.ENCRYPT_MODE, djangoKey);

		Instant inst;

		// Create server socket
		try (DatagramSocket socket = new DatagramSocket(PISport)) {
			System.out.printf("Server will receive packets on port %d %n", PISport);

			// Wait for client packets 
			byte[] buf = new byte[BUFFER_SIZE];
			while (true) {
				// Receive packet
				DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
				socket.receive(clientPacket);
				InetAddress clientAddress = clientPacket.getAddress();
				int clientPort = clientPacket.getPort();
				int clientLength = clientPacket.getLength();
				byte[] clientData = clientPacket.getData();
				System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);
				System.out.printf("%d bytes %n", clientLength);

				// Convert request to string
				String clientText = new String(clientData, 0, clientLength);

				String response = "ok";

				//clientText = clientText.substring(1, clientText.length() - 1)
				System.out.println("\n\n\n" + clientText + "\n\n\n\n");

				// Parse JSON and extract arguments
				JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
				String from, body, to, mac, client, token, keyString;
				{
					//JsonObject infoJson = requestJson.getAsJsonObject("info");
					from = requestJson.get("from").getAsString();
					to = requestJson.get("to").getAsString();
					client = requestJson.get("client").getAsString();
					body = requestJson.get("body").getAsString();
					//mac = requestJson.get("MAC").getAsString();
					token = requestJson.get("token").getAsString();
					//keyString = requestJson.get("SessionKey").getAsString();
				}
				//byte[] keyBytes = djangoDecryptCipher.doFinal(Base64.getDecoder().decode(keyString));
				//SecretKey symKey = new SecretKeySpec(keyBackend, 0, keyBackend.length, "AES");
				//djangoSymCipher.init(Cipher.DECRYPT_MODE, symKey, ivBackend);

				//byte[] macBytes = Base64.getDecoder().decode(mac);
				//String tok = new String(djangoDecryptCipher.doFinal(Base64.getDecoder().decode(token)));
				//String bodyDec = new String(djangoSymCipher.doFinal(Base64.getDecoder().decode(body)));
				//djangoMsgDig.update(bodyDec.getBytes());
				//if (Arrays.equals(macBytes, djangoMsgDig.digest())) {
				//	System.out.println("Confirmed equal body.");
				//} else {
				//	System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(djangoMsgDig.digest()), Arrays.toString(macBytes));	
				//	response = "failed";
				//}
				//if (inst.compareTo(Instant.parse(token)) > 0) {
				//	System.out.println("Old message resent!");
				//	response = "failed";
				//} else {
				//	System.out.println("Confirmed new request.");
				//}
				System.out.printf("Message to '%s', from '%s':%n%s%n", to, from, body);
				System.out.println("response body = " + response);

				//djangoSymCipher.init(Cipher.ENCRYPT_MODE, symKey, ivBackend);
				String[] bodyParts = body.split(",");
				String cardNumber = bodyParts[0];
				String cvc = bodyParts[1];
				String validity = bodyParts[2];
				String amount = bodyParts[3];

				int result = paymentService(serverHost, serverAddress, serverPort, cardNumber, client, amount, PISport);

				pisDecryptCipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());
				inst = Instant.now().plus(15, ChronoUnit.MINUTES);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
				{
					//JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
					responseJson.addProperty("from", "PIS");
					responseJson.addProperty("to", "DjangoWeb");
					//responseJson.add("info", infoJson);

					String bodyText = String.valueOf(result);
					//byte[] cipheredBody = djangoSymCipher.doFinal(bodyText.getBytes());
					//String bodyEnc = Base64.getEncoder().encodeToString(cipheredBody);
					responseJson.addProperty("body", bodyText);

					//djangoMsgDig.update(cipheredBody);
					//String ins = Base64.getEncoder().encodeToString(pisDecryptCipher.doFinal(djangoMsgDig.digest()));
					//responseJson.addProperty("MAC", ins);
					//String Senttoken = Base64.getEncoder().encodeToString(djangoSymCipher.doFinal(inst.toString().getBytes()));
					responseJson.addProperty("Token", inst.toString());
				}
				System.out.println("Response message: " + responseJson);

				// Send response
				byte[] serverData = responseJson.toString().getBytes();
				System.out.printf("%d bytes %n", serverData.length);
				DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientPacket.getAddress(), clientPacket.getPort());
				socket.send(serverPacket);
				System.out.printf("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort());
			}
		}
	}
}