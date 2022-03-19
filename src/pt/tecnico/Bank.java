package pt.tecnico;

import pt.tecnico.API;
import java.io.FileInputStream;
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
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Bank {

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */
	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

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

	public static IvParameterSpec generateIv() {
		byte[] initVec = new byte[16];
		new SecureRandom().nextBytes(initVec);
		return new IvParameterSpec(initVec);
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
		final String CIPHER_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
		final String SYM_ALGO = "AES/CBC/PKCS5Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
		Cipher DecryptCipher = Cipher.getInstance(CIPHER_ALGO);
		KeyPair keys = read("keys/bank_public_key.der", "keys/bank_private_key.der");

		PublicKey pisKey = readPublic("keys/pis_public_key.der");

		Cipher symCipher = Cipher.getInstance(SYM_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

		// Create server socket
		System.out.printf("Server will receive packets on port %d %n", port);
		
		// Wait for client packets 
		while (true) {
			try (DatagramSocket socket = new DatagramSocket(port)) {
				DecryptCipher.init(Cipher.DECRYPT_MODE, keys.getPrivate());
				signCipher.init(Cipher.DECRYPT_MODE, pisKey);
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

				String response = "ok";


				// Parse JSON and extract arguments
				JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
				String from, body, to, mac, client, token, keyString;
				{
					JsonObject infoJson = requestJson.getAsJsonObject("info");
					from = infoJson.get("from").getAsString();
					to = infoJson.get("to").getAsString();
					client = infoJson.get("client").getAsString();
					body = requestJson.get("body").getAsString();
					mac = requestJson.get("MAC").getAsString();
					token = requestJson.get("token").getAsString();
					keyString = requestJson.get("SessionKey").getAsString();
				}

				byte[] keyBytes = DecryptCipher.doFinal(Base64.getDecoder().decode(keyString));
				byte[] ivBytes = Arrays.copyOfRange(keyBytes, keyBytes.length-16, keyBytes.length);
				keyBytes = Arrays.copyOfRange(keyBytes, 0, keyBytes.length-16);
				SecretKey symKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
				IvParameterSpec iv = new IvParameterSpec(ivBytes);
				symCipher.init(Cipher.DECRYPT_MODE, symKey, iv);

				byte[] macBytes = null;
				try {
					macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
				} catch (Exception e) {
					System.out.println("Entity not authenticated!");
				}
				msgDig.update(Base64.getDecoder().decode(body));
				if (Arrays.equals(macBytes, msgDig.digest())) {
					System.out.println("Confirmed content integrity.");
				} else {
					System.out.printf("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes));	
					response = "failed";
				}

				String tok = new String(DecryptCipher.doFinal(Base64.getDecoder().decode(token)));
				if (inst.compareTo(Instant.parse(tok)) > 0) {
					System.out.println("Old message resent!");
					response = "failed";
				} else {
					System.out.println("Confirmed new request.");
				}

				client = new String(symCipher.doFinal(Base64.getDecoder().decode(client)));
				String bodyDec = new String(symCipher.doFinal(Base64.getDecoder().decode(body)));
				System.out.printf("Message to '%s', from '%s':%n%s%n", to, from, bodyDec);
				System.out.println("response body = " + response);


				DecryptCipher.init(Cipher.ENCRYPT_MODE, keys.getPrivate());
				symCipher.init(Cipher.ENCRYPT_MODE, symKey, iv);
				inst = Instant.now().plus(15, ChronoUnit.MINUTES);

				// Create response message
				JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
				{
					JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
					infoJson.addProperty("from", "Bob");
					infoJson.addProperty("to", "Alice");
					responseJson.add("info", infoJson);

					byte[] cipheredBody = symCipher.doFinal(response.getBytes());
					String bodyEnc = Base64.getEncoder().encodeToString(cipheredBody);
					responseJson.addProperty("body", bodyEnc);

					msgDig.update(cipheredBody);
					String ins = Base64.getEncoder().encodeToString(DecryptCipher.doFinal(msgDig.digest()));
					responseJson.addProperty("MAC", ins);
					String Senttoken = Base64.getEncoder().encodeToString(symCipher.doFinal(inst.toString().getBytes()));
					responseJson.addProperty("Token", Senttoken);
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
