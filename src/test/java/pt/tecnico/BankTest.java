package pt.tecnico;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.beans.Transient;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
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
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException; 
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


import com.google.gson.JsonObject;

public class BankTest {

    private API api;
    private Thread bankThread;
    private int port;
    private int bankPort;
    private InetAddress bankAddress;
    private String bankResponse;
    private String username;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey bankPublicKey;
    private Bank bank;

    @BeforeEach
    public void setUp() {
        api = new API();

        port = 9996;
        bankPort = 9997;
        try {
            bankAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        username = "client1";
        String password = "pwd";
        String alias = "client1";

        String privateKeyPath = "keys/" + username + "_private_key.der";
        String publicKeyPath = "keys/" + username + "_public_key.der";
        try {
            privateKey = Client.readPrivate(privateKeyPath);
            publicKey = Client.readPublic(publicKeyPath);
            bankPublicKey = Client.readPublic("keys/bank_public_key.der");
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    @AfterEach
    public void tearDown() {

        if(bankThread != null) {
            bankThread.stop();
        }

        try {
            new FileOutputStream("csv_files/clients.csv").close();
            File client1CompleteTransactionHistoryFile = new File("csv_files/client1_complete_transaction_history.csv");
            if(client1CompleteTransactionHistoryFile.exists()) {
                client1CompleteTransactionHistoryFile.delete();
            }
            File client2CompleteTransactionHistoryFile = new File("csv_files/client2_complete_transaction_history.csv");
            if(client2CompleteTransactionHistoryFile.exists()) {
                client2CompleteTransactionHistoryFile.delete();
            }
            File client1PendingTransactionHistoryFile = new File("csv_files/client1_pending_transaction_history.csv");
            if(client1PendingTransactionHistoryFile.exists()) {
                client1PendingTransactionHistoryFile.delete();
            }
            File client2PendingTransactionHistoryFile = new File("csv_files/client2_pending_transaction_history.csv");
            if(client2PendingTransactionHistoryFile.exists()) {
                client2PendingTransactionHistoryFile.delete();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Test
    public void manipulatedMessage_unitTest() throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException
                                                        , GeneralSecurityException, IOException {

        String clientText = null;
        String DIGEST_ALGO = "SHA-256";
	    String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

        // Timestamps are in UTC
		Instant inst = Instant.now().plus(5, ChronoUnit.MINUTES);

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		Cipher encryptCipher = Cipher.getInstance(CIPHER_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
		signCipher.init(Cipher.ENCRYPT_MODE, privateKey);

		
        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		
        // build info to be digested
        JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
        infoJson.addProperty("to", "BFTB");
		infoJson.addProperty("from", username);
        String bodyText = "mock body text";
        int requestID = 0;
        infoJson.addProperty("body", bodyText);
        infoJson.addProperty("instant", Integer.toString(requestID));

        // Digest the original message
        msgDig.update(infoJson.toString().getBytes());
        String macString = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
        requestJson.addProperty("MAC", macString);

        // Alter the original message
        infoJson.remove("body");
        infoJson.addProperty("body", "Altered body");

        // Add the altered message to the Json to be sent
        requestJson.add("info", infoJson);
		



        String response[] = bank.receiveMessageAndCheckSafety(requestJson.toString());

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), response[0]);
    }
    
}

