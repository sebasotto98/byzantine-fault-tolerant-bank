package pt.tecnico;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.security.MessageDigest;
import java.util.List;

import javax.crypto.Cipher;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class BankTest {

    private static final List<String> bankNames;
    static {
        bankNames = new ArrayList<>();
        bankNames.add("bftb1");
    }
    private static final List<Integer> bankPorts;
    static {
        bankPorts = new ArrayList<>();
        bankPorts.add(5000);
    }

    private final String username = "client1";
    private PrivateKey privateKey;

    @BeforeEach
    public void setUp() {
        String privateKeyPath = "keys/" + username + "_private_key.der";
        try {
            privateKey = Client.readPrivate(privateKeyPath);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    @AfterEach
    public void tearDown() {
        try {
            new FileOutputStream(bankNames.get(0) + "_csv_files/clients.csv").close();
            new FileOutputStream(bankNames.get(0) + "_csv_files/signatures.csv").close();
            new FileOutputStream(bankNames.get(0) + "_csv_files/transactionId.csv").close();
            new FileOutputStream(bankNames.get(0) + "_csv_files/requestIDs.csv").close();
            File client1CompleteTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client1_complete_transaction_history.csv");
            if(client1CompleteTransactionHistoryFile.exists()) {
                client1CompleteTransactionHistoryFile.delete();
            }
            File client2CompleteTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client2_complete_transaction_history.csv");
            if(client2CompleteTransactionHistoryFile.exists()) {
                client2CompleteTransactionHistoryFile.delete();
            }
            File client1PendingTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client1_pending_transaction_history.csv");
            if(client1PendingTransactionHistoryFile.exists()) {
                client1PendingTransactionHistoryFile.delete();
            }
            File client2PendingTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client2_pending_transaction_history.csv");
            if(client2PendingTransactionHistoryFile.exists()) {
                client2PendingTransactionHistoryFile.delete();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Test
    public void TestManipulatedMessage_detected_success() throws GeneralSecurityException, IOException {
        String DIGEST_ALGO = "SHA-256";
	    String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";

		MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);

		Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);
        signCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		
        // build info to be digested
        JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
        infoJson.addProperty("to", bankNames.get(0));
		infoJson.addProperty("from", username);
        String bodyText = "mock body text";
        infoJson.addProperty("body", bodyText);

        int requestID = 10000;
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/requestIDs.csv", new String[]{username, String.valueOf(requestID-1)}, true);
        infoJson.addProperty("requestId", Integer.toString(requestID));

        String verificationString = bankNames.get(0) + "," + username + "," + requestID + "," + bodyText;
        String signature = Base64.getEncoder().encodeToString(signCipher.doFinal(verificationString.getBytes()));
        infoJson.addProperty("signature", signature);

        msgDig.update(infoJson.toString().getBytes());
        String macString = Base64.getEncoder().encodeToString(signCipher.doFinal(msgDig.digest()));
        requestJson.addProperty("MAC", macString);

        // Alter the original message
        infoJson.remove("body");
        infoJson.addProperty("body", "Altered body");

        // Add the altered message to the Json to be sent
        requestJson.add("info", infoJson);

        WorkerThread workerThread = new WorkerThread(bankPorts.get(0), bankNames.get(0), signCipher, msgDig, privateKey);

        String[] response = workerThread.receiveMessageAndCheckSafety(requestJson.toString());

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), response[0]);
    }
    
}