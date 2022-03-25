package pt.tecnico;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
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
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opencsv.CSVWriter;

public class Bank {

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However, the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header).
	 */
	private static final int BUFFER_SIZE = (64 * 1024 - 1) - 8 - 20;

	private static final int INITIAL_ACCOUNT_BALANCE = 1000;

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

	public static PrivateKey readPrivate(String privateKeyPath) throws GeneralSecurityException, IOException {
		System.out.println("Reading private key from file " + privateKeyPath + " ...");
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
					Integer.toString(INITIAL_ACCOUNT_BALANCE)});

			return ActionLabel.ACCOUNT_CREATED.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.SEND_AMOUNT.getLabel())) { // 1 - amount, 2 - receiver
			return ActionLabel.TODO.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.CHECK_ACCOUNT.getLabel())) {
			return ActionLabel.TODO.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.RECEIVE_AMOUNT.getLabel())) {
			return ActionLabel.TODO.getLabel();
		} else if(bodyArray[0].equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {
			return ActionLabel.TODO.getLabel();
		} else {
			return ActionLabel.UNKNOWN_FUNCTION.getLabel();
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
		final String DIGEST_ALGO = "SHA-256";
		final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);

		PublicKey pubKey = readPublic("keys/bank_public_key.der");
		PrivateKey privKey = readPrivate("keys/bank_private_key.der");
		PublicKey pubClientKey = null; //readPublic("keys/pis_public_key.der");

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

		// Create server socket
		System.out.printf("Server will receive packets on port %d %n", port);
		
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
				System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);
				System.out.printf("%d bytes %n", clientLength);

				inst = Instant.now();

				// Convert request to string
				String clientText = new String(clientData, 0, clientLength);
				System.out.println("Received request: " + clientText);

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

				String response = "failed";
				String publicClientPath = "keys/" + from + "_public_key.der";
				pubClientKey = readPublic(publicClientPath);
				decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
				signCipher.init(Cipher.DECRYPT_MODE, pubClientKey);

				byte[] macBytes = null;
				try {
					macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
				} catch (Exception e) {
					System.out.println("Entity not authenticated!");
				}
				msgDig.update(infoClientJson.toString().getBytes());
				if (Arrays.equals(macBytes, msgDig.digest())) {
					response = setResponse(bodyArray, from);
					System.out.println("Confirmed content integrity.");
				} else {
					System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes));
				}

				System.out.printf("Message to '%s', from '%s':%n%s%n", to, from, body);
				System.out.println("response body = " + response);

				decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
				inst = Instant.now().plus(15, ChronoUnit.MINUTES);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();

				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("from", "BFTB");
				infoJson.addProperty("to", from);
				infoJson.addProperty("instant", inst.toString());
				infoJson.addProperty("body", response);

				responseJson.add("info", infoJson);

				msgDig.update(infoJson.toString().getBytes());
				String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
				responseJson.addProperty("MAC", ins);

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

	private static void writeToCSV(String filePath, String[] values) {
		try {
			FileWriter outputFile = new FileWriter(filePath, true);
			CSVWriter writer = new CSVWriter(outputFile);
			writer.writeNext(values);
			writer.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
}