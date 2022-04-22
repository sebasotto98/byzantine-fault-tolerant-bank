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
import java.security.PublicKey;
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
    private static final int faults = 0;

    private API api;
    private Thread bankThread;
    private final int port = 6000;
    private InetAddress bankAddress;
    private String bankResponse;
    private final String username = "client1";
    private PrivateKey privateKey;
    private PublicKey bankPublicKey;

    @BeforeEach
    public void setUp() {
        api = new API(bankNames, bankPorts, faults);

        try {
            bankAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        String privateKeyPath = "keys/" + username + "_private_key.der";
        try {
            privateKey = Client.readPrivate(privateKeyPath);
            bankPublicKey = Client.readPublic("keys/" + bankNames.get(0) + "_public_key.der");
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
    public void openAccount_accountCreated_success() {

        BankHelper bankHelper = new BankHelper(bankNames.get(0));
        bankThread = new Thread(bankHelper);
        bankThread.start();

        try {
            bankResponse = api.openAccount(privateKey, port, bankPorts.get(0), bankAddress, bankPublicKey, username, -1, bankNames.get(0));
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.ACCOUNT_CREATED.getLabel(), bankResponse);

    }

    @Test
    public void openAccount_accountCreated_failure() {

        try {
            bankResponse = api.openAccount(privateKey, port, bankPorts.get(0), bankAddress, bankPublicKey, username, -1, bankNames.get(0));
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }

        Assertions.assertEquals(ActionLabel.FAIL.getLabel(), bankResponse);
    }

    /* TODO: Implement the following tests

    @Test
    public void openAccount_clientsFileCreated_success() {

    }

    @Test
    public void openAccount_clientsFileCreated_failure() {

    }

    @Test
    public void openAccount_completeTransactionsHistoryFileCreated_success() {

    }

    @Test
    public void openAccount_completeTransactionsHistoryFileCreated_failure() {

    }

    @Test
    public void openAccount_pendingTransactionsHistoryFileCreated_success() {

    }

    @Test
    public void openAccount_pendingTransactionsHistoryFileCreated_failure() {

    }

    @Test
    public void sendAmount_amountSent_success() {

    }

    @Test
    public void sendAmount_amountSent_failure() {

    }

    @Test
    public void checkAmount_success() {

    }

    @Test
    public void checkAmount_failure() {

    }

    @Test
    public void receiveAmount_amountReceived_success() {

    }

    @Test
    public void receiveAmount_amountReceived_failure() {

    }

    @Test
    public void auditAccount_success() {

    }

    @Test
    public void auditAccount_failure() {

    }
    */
}
