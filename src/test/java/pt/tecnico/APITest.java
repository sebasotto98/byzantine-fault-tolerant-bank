package pt.tecnico;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public class APITest {

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
    private static final int faults = 1;

    private API api;
    private Thread bankThread;
    private final int port = 6000;
    private InetAddress bankAddress;
    private String bankResponse;
    private final String username = "client1";
    private final String usernameDest = "client2";
    private PrivateKey privateKey;
    private PrivateKey destPrivateKey;

    @BeforeEach
    public void setUp() {
        api = new API(bankNames, bankPorts, faults);

        try {
            bankAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        String privateKeyPath = "keys/" + username + "_private_key.der";
        String destPrivateKeyPath = "keys/" + usernameDest + "_private_key.der";
        try {
            privateKey = Client.readPrivate(privateKeyPath);
            destPrivateKey = Client.readPrivate(destPrivateKeyPath);
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
    public void openAccountTest_accountCreated_success() {

        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        try {
            bankResponse = api.openAccount(privateKey, port, bankAddress, username, -1);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.ACCOUNT_CREATED.getLabel(), bankResponse);

    }

    @Test
    public void openAccountTest_accountCreated_failure() {

        try {
            bankResponse = api.openAccount(privateKey, port, bankAddress, username, -1);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void sendAmountTest_amountSent_success() {
        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{username, "1000", "1000"}, false);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{usernameDest, "1000", "1000"}, true);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/transactionId.csv", new String[]{String.valueOf(0)}, true);

        try {
            bankResponse = api.sendAmount(privateKey, port, bankAddress, -1, username, 1000, usernameDest);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.SUCCESS.getLabel(), bankResponse);
    }

    @Test
    public void sendAmountTest_amountSent_failure() {
        try {
            bankResponse = api.sendAmount(privateKey, port, bankAddress, -1, username, 1000, usernameDest);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void checkAccountTest_checkDone_success() {

        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        File client1PendingTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client1_pending_transaction_history.csv");
        try {
            client1PendingTransactionHistoryFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
        int requestID = 10000;
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/requestIDs.csv", new String[]{username, String.valueOf(requestID-1)}, true);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{username, "1000", "1000"}, false);
        try {
            bankResponse = api.checkAccount(privateKey, port, bankAddress, username, requestID, username);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertNotEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void checkAccountTest_checkDone_failure() {
        try {
            bankResponse = api.checkAccount(privateKey, port, bankAddress, username, 1, username);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void receiveAmountTest_amountReceived_success() {
        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        int requestID = 10000;
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{username, "1000", "1000"}, false);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{usernameDest, "1000", "1000"}, true);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/transactionId.csv", new String[]{String.valueOf(0)}, true);

        try {
            api.sendAmount(privateKey, port, bankAddress, requestID, username, 500, usernameDest);
            bankResponse = api.receiveAmount(destPrivateKey, port, bankAddress, usernameDest, requestID+1, 1);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.SUCCESS.getLabel(), bankResponse);
    }

    @Test
    public void receiveAmountTest_amountReceived_failure() {
        try {
            bankResponse = api.receiveAmount(privateKey, port, bankAddress, username, -1, 1);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void auditAccountTest_auditDone_success() {
        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        File client1CompleteTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client1_complete_transaction_history.csv");
        File client1PendingTransactionHistoryFile = new File(bankNames.get(0) + "_csv_files/client1_pending_transaction_history.csv");
        try {
            client1CompleteTransactionHistoryFile.createNewFile();
            client1PendingTransactionHistoryFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
        int requestID = 10000;
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/requestIDs.csv", new String[]{username, String.valueOf(requestID-1)}, true);
        WorkerThread.writeToCSV(bankNames.get(0) + "_csv_files/clients.csv", new String[]{username, "1000", "1000"}, false);

        try {
            bankResponse = api.auditAccount(privateKey, port, bankAddress, username, requestID, username);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertNotEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    @Test
    public void auditAccountTest_auditDone_failure() {
        try {
            bankResponse = api.auditAccount(privateKey, port, bankAddress, username, -1, username);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

}
