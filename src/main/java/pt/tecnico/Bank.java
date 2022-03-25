package pt.tecnico;

import java.io.File;
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

	private static String setResponse(String body, PublicKey pubClientKey) {
		if(body.equals("OpenAccount")) {
			writeToCSV("csv_files/clients.csv", new String[]{pubClientKey.getEncoded().toString(), "1000", "1000"});
			return "AccountCreated";
		} else {
			return "UNKNOWN_FUNCTION";
		}
	}

	public static void main(String[] args) throws Exception {
		// Check arguments
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			//System.err.printf("Usage: java %s port%n", JsonServer.class.getName());
			return;
		}
		final int port = Integer.parseInt(args[0]);
		Instant inst;

		// Hash and (de)cipher algorithms initialization
		final String DIGEST_ALGO = "SHA-256";
		final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
		//final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);

		PublicKey pubKey = readPublic("keys/bank_public_key.der");
		PrivateKey privKey = readPrivate("keys/bank_private_key.der");
		PublicKey pubClientKey = null; //readPublic("keys/pis_public_key.der");

		//Cipher symCipher = Cipher.getInstance(SYM_ALGO);

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
				//client = infoJson.get("client").getAsString();
				body = infoClientJson.get("body").getAsString();
				instant = infoClientJson.get("instant").getAsString();
				mac = requestJson.get("MAC").getAsString();
				//token = requestJson.get("token").getAsString();
				//keyString = requestJson.get("SessionKey").getAsString();
/**
				byte[] keyBytes = decryptCipher.doFinal(Base64.getDecoder().decode(keyString));
				byte[] ivBytes = Arrays.copyOfRange(keyBytes, keyBytes.length-16, keyBytes.length);
				keyBytes = Arrays.copyOfRange(keyBytes, 0, keyBytes.length-16);
				SecretKey symKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
				IvParameterSpec iv = new IvParameterSpec(ivBytes);
				symCipher.init(Cipher.DECRYPT_MODE, symKey, iv);
*/
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
					response = setResponse(body, pubClientKey);
					System.out.println("Confirmed content integrity.");
				} else {
					System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes));
				}
/**
				String tok = new String(decryptCipher.doFinal(Base64.getDecoder().decode(token)));
				if (inst.compareTo(Instant.parse(tok)) > 0) {
					System.out.println("Old message resent!");
					response = "failed";
				} else {
					System.out.println("Confirmed new request.");
				}
*/
				//client = new String(symCipher.doFinal(Base64.getDecoder().decode(client)));
				//String bodyDec = new String(symCipher.doFinal(Base64.getDecoder().decode(body)));
				System.out.printf("Message to '%s', from '%s':%n%s%n", to, from, body);
				System.out.println("response body = " + response);

				decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
				//symCipher.init(Cipher.ENCRYPT_MODE, symKey, iv);
				inst = Instant.now().plus(15, ChronoUnit.MINUTES);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();

				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("from", "BFTB");
				infoJson.addProperty("to", from);
				infoJson.addProperty("instant", inst.toString());
				infoJson.addProperty("body", response);

				responseJson.add("info", infoJson);

				//byte[] cipheredBody = symCipher.doFinal(response.getBytes());
				//String bodyEnc = Base64.getEncoder().encodeToString(cipheredBody);

				msgDig.update(infoJson.toString().getBytes());
				String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
				responseJson.addProperty("MAC", ins);
				//String sentToken = Base64.getEncoder().encodeToString(symCipher.doFinal(inst.toString().getBytes()));
				//responseJson.addProperty("Token", sentToken);

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