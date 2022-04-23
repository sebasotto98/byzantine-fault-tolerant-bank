package pt.tecnico;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opencsv.CSVWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class WorkerThread extends Thread {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

    private static final int INITIAL_ACCOUNT_BALANCE = 1000;
    private static final int BUFFER_SIZE = (64 * 1024 - 1) - 8 - 20;
    private static final int SOCKET_TIMEOUT = 5000;

    private static final String DIGEST_ALGO = "SHA-256";
    private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
    private static final String CLIENTS_CSV_FILE_PATH = "_csv_files/clients.csv";
    private static final String REQUEST_ID_CSV_FILE_PATH = "_csv_files/requestIDs.csv";
    private static final String SIGNATURES_CSV_FILE_PATH = "_csv_files/signatures.csv";
    private static final String TRANSACTION_ID_FILE_PATH = "_csv_files/transactionId.csv";
    private static final String COMPLETED_TRANSACTION_SIGN_FILE_PATH = "_csv_files/completedSignedTransactions.csv";
    private static final String PENDING_TRANSACTION_SIGN_FILE_PATH = "_csv_files/pendingSignedTransactions.csv";

    private final DatagramPacket clientPacket;

    private final String name;
    private final Cipher decryptCipher;
    private final MessageDigest msgDig;
    private final PrivateKey privKey;
    private final AtomicInteger bankRequestId;
    private final SharedBankVars bankVars;

    private final Object clientsFileLock;
    private final Object requestIdFileLock;
    private final Object signaturesFileLock;
    private final Object transactionIdFileLock;

    private InetAddress clientAddress;
    private DatagramSocket socket;
    private int clientPort;

    public WorkerThread(int socketPort, String name, Cipher decryptCipher, MessageDigest msgDig, PrivateKey privKey) {
        this.bankVars = new SharedBankVars();

        this.clientPacket = null;

        this.decryptCipher = decryptCipher;
        this.msgDig = msgDig;
        this.privKey = privKey;

        this.name = name;

        this.bankRequestId = this.bankVars.getBankRequestId();

        this.clientsFileLock = this.bankVars.getClientsFileLock();
        this.requestIdFileLock = this.bankVars.getRequestIdFileLock();
        this.signaturesFileLock = this.bankVars.getSignaturesFileLock();
        this.transactionIdFileLock = this.bankVars.getTransactionIdFileLock();

        try {
            this.socket = new DatagramSocket(socketPort);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    public WorkerThread(int socketPort, DatagramPacket clientPacket, String name,
                        Cipher DecryptCipher, MessageDigest msgDig, PrivateKey privKey,
                        SharedBankVars bankVars) {

        this.bankVars = bankVars;

        this.clientPacket = clientPacket;

        this.decryptCipher = DecryptCipher;
        this.msgDig = msgDig;
        this.privKey = privKey;

        this.name = name;

        this.bankRequestId = this.bankVars.getBankRequestId();

        this.clientsFileLock = this.bankVars.getClientsFileLock();
        this.requestIdFileLock = this.bankVars.getRequestIdFileLock();
        this.signaturesFileLock = this.bankVars.getSignaturesFileLock();
        this.transactionIdFileLock = this.bankVars.getTransactionIdFileLock();

        try {
            this.socket = new DatagramSocket(socketPort);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
            clientAddress = clientPacket.getAddress();
            clientPort = clientPacket.getPort();
            int clientLength = clientPacket.getLength();
            byte[] clientData = clientPacket.getData();
            logger.info(String.format("Received request packet from %s:%d!%n", clientAddress, clientPort));
            logger.info(String.format("%d bytes %n", clientLength));

            // Convert request to string
            String clientText = new String(clientData, 0, clientLength);
            logger.info("Received request: " + clientText);

            String[] response = receiveMessageAndCheckSafety(clientText);

            // Create response message
            JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();

            JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
            infoJson.addProperty("from", name);
            infoJson.addProperty("to", response[1]);
            infoJson.addProperty("requestId", Integer.toString(bankRequestId.get()));
            infoJson.addProperty("body", response[0]);
            infoJson.addProperty("token", response[2]);

            bankVars.incrementBankRequestID();

            responseJson.add("info", infoJson);

            if (decryptCipher != null && msgDig != null) {
                decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
                msgDig.update(infoJson.toString().getBytes());
                String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
                responseJson.addProperty("MAC", ins);
                synchronized (signaturesFileLock) {
                    //Store signature
                    writeToCSV(this.name + SIGNATURES_CSV_FILE_PATH, new String[]{name, response[1], ins}, true);
                }
            }

            logger.info("Response message: " + responseJson);

            // Send response
            byte[] serverData = responseJson.toString().getBytes();
            logger.info(String.format("%d bytes %n", serverData.length));
            DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientAddress, clientPort);
            socket.send(serverPacket);
            socket.close();
            logger.info(String.format("Response packet sent to %s:%d!%n", clientAddress, clientPort));
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
    }

    public String[] receiveMessageAndCheckSafety(String clientText) throws GeneralSecurityException, IOException {
        String[] response = new String[3];

        PublicKey pubClientKey = null;
        MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
        Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);
        Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

        // Parse JSON and extract arguments
        JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
        String from, body, to, mac, requestId, signature;

        JsonObject infoClientJson = requestJson.getAsJsonObject("info");
        to = infoClientJson.get("to").getAsString();
        from = infoClientJson.get("from").getAsString();
        body = infoClientJson.get("body").getAsString();
        requestId = infoClientJson.get("requestId").getAsString();
        mac = requestJson.get("MAC").getAsString();

        signature = infoClientJson.get("signature").getAsString();

        String[] bodyArray = body.split(",");

        response[0] = ActionLabel.FAIL.getLabel();
        String publicClientPath = "keys/" + from + "_public_key.der";
        pubClientKey = readPublic(publicClientPath);
        decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
        signCipher.init(Cipher.DECRYPT_MODE, pubClientKey);

        int idReceived = Integer.parseInt(requestId);

        String id;
        synchronized (requestIdFileLock) {
            id = getCurrentRequestIdFrom(from);
        }

        int clientID = Integer.parseInt(id);


        if (!bodyArray[0].equals(ActionLabel.OPEN_ACCOUNT.getLabel()) &&
                !bodyArray[0].equals(ActionLabel.REQUEST_BANK_ID.getLabel()) &&
                !bodyArray[0].equals(ActionLabel.REQUEST_MY_ID.getLabel())) {
            if (clientID == -1) {
                logger.error("Client has no request ID");
                response[0] = ActionLabel.FAIL.getLabel();
            } else if (idReceived <= clientID) {
                logger.info("Message is duplicate, shall be ignored");
                response[0] = ActionLabel.FAIL.getLabel();
            } else if (idReceived != Integer.MAX_VALUE) { //valid request id
                synchronized (requestIdFileLock) {
                    updateRequestID(from, requestId);
                }
            }
        }

        byte[] macBytes;
        try {
            macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
        } catch (Exception e) {
            logger.error("Error: ", e);
            logger.info("Entity not authenticated!");
            return response;
        }
        msgDig.update(infoClientJson.toString().getBytes());
        if (Arrays.equals(macBytes, msgDig.digest())) {
            logger.info("Confirmed content integrity.");
        } else {
            logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes)));
            return response;
        }

        synchronized (signaturesFileLock) {
            //Store signature
            writeToCSV(this.name + SIGNATURES_CSV_FILE_PATH, new String[]{from, name, mac}, true);
        }


        response[1] = from;
        response[2] = requestId;

        if (bodyArray[0].equals(ActionLabel.WRITE_BACK.getLabel())) {
            response[0] = handleWriteBackRequest(body);
        } else {
            response[0] = setResponse(bodyArray, from, signature);
        }

        logger.info(String.format("Message to '%s', from '%s':%n%s%n", to, from, body));

        return response;
    }

    private String getCurrentRequestIdFrom(String username) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client;
        try {
            fileReader = new FileReader(this.name + REQUEST_ID_CSV_FILE_PATH);
            reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                client = line.split(",");
                if (client[0].equals(username)) {
                    fileReader.close();
                    reader.close();
                    return client[1];
                }
            }
            fileReader.close();
            reader.close();
        } catch (IOException e) {
            logger.info("Error reading requestId file.");
        }
        return "-2";
    }

    private void updateRequestID(String username, String requestID) {
        //get list of clients
        FileReader fileReader;
        BufferedReader reader;
        String[] client;
        List<String[]> clients = new ArrayList<>();
        try {
            fileReader = new FileReader(this.name + REQUEST_ID_CSV_FILE_PATH);
            reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                client = line.split(",");
                clients.add(client);
            }
            fileReader.close();
            reader.close();
        } catch (IOException e) {
            logger.info("Error reading requestId file.");
        }

        for (String[] c : clients) {
            if (c[0].equals(username)) {
                c[1] = requestID;
                break;
            }
        }
        boolean flag = false;
        for (String[] c : clients) {
            writeToCSV(this.name + REQUEST_ID_CSV_FILE_PATH, c, flag);
            flag = true;
        }
    }

    private String setResponse(String[] bodyArray, String username, String signature)
            throws IOException, GeneralSecurityException {
        //bodyArray -> 1-amount, 2-receiver
        if (bodyArray[0].equals(ActionLabel.OPEN_ACCOUNT.getLabel())) {
            return handleOpenAccount(username);
        } else if (bodyArray[0].equals(ActionLabel.SEND_AMOUNT.getLabel())) {
            return handleSendAmountRequest(username, bodyArray[1], bodyArray[2], signature);
        } else if (bodyArray[0].equals(ActionLabel.CHECK_ACCOUNT.getLabel())) {
            return handleCheckAccountRequest(bodyArray[1]);
        } else if (bodyArray[0].equals(ActionLabel.RECEIVE_AMOUNT.getLabel())) {
            return handleReceiveAmountRequest(username, bodyArray[1], signature);
        } else if (bodyArray[0].equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {
            return handleAuditAccountRequest(bodyArray[1]);
        } else if (bodyArray[0].equals(ActionLabel.REQUEST_MY_ID.getLabel())) {
            String clientId;
            synchronized (requestIdFileLock) {
                clientId = getCurrentRequestIdFrom(username);
            }
            return clientId + "," + bankRequestId;
        } else {
            return ActionLabel.UNKNOWN_FUNCTION.getLabel();
        }
    }

    private String handleOpenAccount(String username) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);

                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    if (client[0].equals(username)) {
                        fileReader.close();
                        reader.close();
                        return ActionLabel.DUPLICATE_USERNAME.getLabel();
                    }
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("openAccount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }

        synchronized (clientsFileLock) {
            writeToCSV(this.name + CLIENTS_CSV_FILE_PATH, new String[]{username, Integer.toString(INITIAL_ACCOUNT_BALANCE),
                    Integer.toString(INITIAL_ACCOUNT_BALANCE)}, true);
        }
        createTransactionHistoryFiles(username);

        synchronized (requestIdFileLock) {
            writeToCSV(this.name + REQUEST_ID_CSV_FILE_PATH, new String[]{username, Integer.toString(0)}, true);
        }
        return ActionLabel.ACCOUNT_CREATED.getLabel();
    }

    private String handleAuditAccountRequest(String owner) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client = null;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);

                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    if (client[0].equals(owner)) {
                        break;
                    }
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("auditAccount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }

        if (client == null) {
            return ActionLabel.CLIENT_NOT_FOUND.getLabel();
        } else {
            StringBuilder response = new StringBuilder();
            for (int i = 0; i < client.length; i++) {
                String s = client[i];
                response.append(s);
                if (i != client.length - 1) { //last one doesn't need ","
                    response.append(",");
                }
            }
            String ownerPendingTransactionsPath = this.name + "_csv_files/" + owner + "_complete_transaction_history.csv";
            try {
                synchronized (bankVars.getClientLock(owner)) {
                    fileReader = new FileReader(ownerPendingTransactionsPath);
                    reader = new BufferedReader(fileReader);
                    String line;

                    while ((line = reader.readLine()) != null) { //transactions separated with ";"
                        response.append(";");
                        response.append(line);
                    }
                    fileReader.close();
                    reader.close();
                }
                return response.toString();
            } catch (IOException e) {
                logger.info("auditAccount: Error reading complete transactions file.");
                return ActionLabel.FAIL.getLabel();
            }
        }
    }

    private String handleCheckAccountRequest(String owner) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client = null;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);
                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    if (client[0].equals(owner)) {
                        break;
                    }
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("checkAccount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }

        if (client == null) {
            return ActionLabel.CLIENT_NOT_FOUND.getLabel();
        } else {
            StringBuilder response = new StringBuilder();
            for (int i = 0; i < client.length; i++) {
                String s = client[i];
                response.append(s);
                if (i != client.length - 1) { //last one doesn't need ","
                    response.append(",");
                }
            }
            String ownerPendingTransactionsPath = this.name + "_csv_files/" + owner + "_pending_transaction_history.csv";
            try {
                synchronized (bankVars.getClientLock(owner)) {
                    fileReader = new FileReader(ownerPendingTransactionsPath);
                    reader = new BufferedReader(fileReader);
                    String line;

                    while ((line = reader.readLine()) != null) { //transactions separated with ";"
                        response.append(";");
                        response.append(line);
                    }
                    fileReader.close();
                    reader.close();
                }
                return response.toString();
            } catch (IOException e) {
                logger.info("checkAccount: Error reading pending transactions file.");
                return ActionLabel.FAIL.getLabel();
            }
        }
    }

    private String handleSendAmountRequest(String username, String amount, String receiver, String signature) throws GeneralSecurityException, IOException {
        //get account information
        String[] client;
        List<String[]> clients = new ArrayList<>();
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);
                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    clients.add(client);
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("sendAmount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }

        boolean senderFound = false;
        boolean receiverFound = false;
        for (String[] c : clients) {
            System.out.print("c[0]:");
            System.out.println("|" + c[0] + "|");
            if (c[0].equals(username)) {
                //c -> 0-username, 1-available amount, 2-book
                //check negative amount
                if (Float.parseFloat(amount) < 0) {
                    return ActionLabel.NEGATIVE_AMOUNT.getLabel();
                }
                //check available amount
                float final_amount = Float.parseFloat(c[1]) - Float.parseFloat(amount);
                if (final_amount >= 0) {
                    c[1] = String.valueOf(final_amount);
                } else {
                    return ActionLabel.INSUFFICIENT_AMOUNT.getLabel();
                }
                senderFound = true;
            } else if (c[0].equals(receiver)) {
                receiverFound = true;
            }
        }

        if (receiverFound && senderFound) {
            //this boolean is used to overwrite file. First call to write overwrites files and following call just append
            boolean flag = false;
            synchronized (clientsFileLock) {
                for (String[] c : clients) {
                    writeToCSV(this.name + CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
                    flag = true;
                }
            }

            String receiverPendingTransactionsFile = this.name + "_csv_files/" + receiver + "_pending_transaction_history.csv";
            String senderPendingTransactionsFile = this.name + "_csv_files/" + username + "_pending_transaction_history.csv";

            int transactionId = readTransactionIdAndIncrement();
            if (transactionId == -1) {
                logger.info("sendAmount: Error reading transaction id file.");
                return ActionLabel.FAIL.getLabel();
            }

            String[] transaction = new String[6];
            transaction[0] = String.valueOf(transactionId);
            transaction[1] = new Timestamp(System.currentTimeMillis()).toString();
            transaction[2] = username;
            transaction[3] = receiver;
            transaction[4] = amount;
            transaction[5] = signature;

            bankVars.incrementTransactionId();
            synchronized (bankVars.getClientLock(receiver)) {
                synchronized (bankVars.getClientLock(username)) {
                    writeToCSV(receiverPendingTransactionsFile, transaction, true);
                    writeToCSV(senderPendingTransactionsFile, transaction, true);
                }
            }
            return ActionLabel.PENDING_TRANSACTION.getLabel();
        } else {
            logger.info("sendAmount: Sender/Receiver client not found!");
            return ActionLabel.CLIENT_NOT_FOUND.getLabel();
        }
    }

    private String handleReceiveAmountRequest(String username, String id, String signature) {

        //get account information
        String[] client;
        List<String[]> clients = new ArrayList<>();
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);
                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    clients.add(client);
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("receiveAmount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }


        boolean usernameFound = false;
        for (String[] c : clients) {
            System.out.print("c[0]:");
            System.out.println("|" + c[0] + "|");
            if (c[0].equals(username)) {
                //c -> 0-username, 1-available amount, 2-book
                usernameFound = true;
            }
        }

        String[] pendingTransaction;
        String usernamePendingTransactionsPath = this.name + "_csv_files/" + username + "_pending_transaction_history.csv";
        List<String[]> pendingTransactions = new ArrayList<>();
        try {
            synchronized (bankVars.getClientLock(username)) {
                fileReader = new FileReader(usernamePendingTransactionsPath);
                reader = new BufferedReader(fileReader);
                String line;
                while ((line = reader.readLine()) != null) {
                    pendingTransaction = line.split(",");
                    pendingTransactions.add(pendingTransaction);
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("receiveAmount: Error reading clients file.");
            return ActionLabel.FAIL.getLabel();
        }

        String sender = null;
        boolean transactionFound = false;
        boolean receiverFound = false;
        boolean senderFound = false;
        String[] receiverTransaction = null;
        for (String[] t : pendingTransactions) {
            System.out.print("c[0]:");
            System.out.println("|" + t[0] + "|");
            if (t[0].equals(id)) {
                //c -> 0-id, 1-timestamp, 2-sender 3-receiver 4-amount 5-signature
                //check if client is receiver
                if (t[3].equals(username)) {
                    transactionFound = true;
                    for (String[] c : clients) {
                        System.out.print("c[0]:");
                        System.out.println("|" + c[0] + "|");
                        if (c[0].equals(username)) {
                            //c -> 0-username, 1-available amount, 2-book
                            receiverFound = true;
                            float available_final_amount = Float.parseFloat(c[1]) + Float.parseFloat(t[4]);
                            float book_final_amount = Float.parseFloat(c[1]) + Float.parseFloat(t[4]);
                            c[1] = String.valueOf(available_final_amount);
                            c[2] = String.valueOf(book_final_amount);
                        } else if (c[0].equals(t[2])) {
                            senderFound = true;
                            sender = c[0];
                            float final_amount = Float.parseFloat(c[2]) - Float.parseFloat(t[4]);
                            c[2] = String.valueOf(final_amount);
                        }
                    }
                    receiverTransaction = t;
                } else {
                    return ActionLabel.CLIENT_NOT_RECEIVER.getLabel();
                }

            }
        }

        if (usernameFound && transactionFound && senderFound && receiverFound) {
            //this boolean is used to overwrite file. First call to write overwrites files and following call just append
            boolean flag = false;
            synchronized (clientsFileLock) {
                for (String[] c : clients) {
                    writeToCSV(this.name + CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
                    flag = true;
                }
            }

            // updating transactions in
            String[] pendingTransactionSender;
            String usernamePendingTransactionsSenderPath = this.name + "_csv_files/" + sender + "_pending_transaction_history.csv";
            List<String[]> pendingTransactionsSender = new ArrayList<>();
            String[] transactionInSender = null;
            try {
                synchronized (bankVars.getClientLock(sender)) {
                    fileReader = new FileReader(usernamePendingTransactionsSenderPath);
                    reader = new BufferedReader(fileReader);
                    String line;
                    while ((line = reader.readLine()) != null) {
                        pendingTransactionSender = line.split(",");
                        if (pendingTransactionSender[0].equals(id)) {
                            transactionInSender = pendingTransactionSender;
                        }
                        pendingTransactionsSender.add(pendingTransactionSender);

                    }
                    fileReader.close();
                    reader.close();
                }
            } catch (IOException e) {
                logger.info("receiveAmount: Error reading clients file.");
                return ActionLabel.FAIL.getLabel();
            }

            pendingTransactions.remove(receiverTransaction);
            pendingTransactionsSender.remove(transactionInSender);

            String receiverPendingTransactionsFile = this.name + "_csv_files/" + username + "_pending_transaction_history.csv";
            String receiverTransactionsFile = this.name + "_csv_files/" + username + "_complete_transaction_history.csv";
            String senderPendingTransactionsFile = this.name + "_csv_files/" + sender + "_pending_transaction_history.csv";
            String senderCompletedTransactionsFile = this.name + "_csv_files/" + sender + "_complete_transaction_history.csv";

            logger.info("Receiver pending " + pendingTransactions.size() + "; sender pending " + pendingTransactionsSender.size());
            logger.info("");
            logger.info("");
            logger.info("");
            logger.info("");

            synchronized (bankVars.getClientLock(username)) {
                synchronized (bankVars.getClientLock(sender)) {
                    if (pendingTransactions.size() == 0) {
                        // clear all contents of file
                        try {
                            File pendingTransactionHistoryFile = new File(this.name + "_csv_files/" + username + "_pending_transaction_history.csv");
                            pendingTransactionHistoryFile.delete();
                            pendingTransactionHistoryFile.createNewFile();
                        } catch (IOException e) {
                            logger.info("receiveAmount: Error reading clients file.");
                            return ActionLabel.FAIL.getLabel();
                        }
                    } else {
                        flag = false;
                        for (String[] t : pendingTransactions) {
                            writeToCSV(receiverPendingTransactionsFile, t, flag); //rewrite pending transaction of receiver file
                            flag = true;
                        }
                    }

                    if (pendingTransactionsSender.size() == 0) {
                        // clear all contents of file
                        try {
                            File pendingTransactionHistoryFile = new File(this.name + "_csv_files/" + sender + "_pending_transaction_history.csv");
                            pendingTransactionHistoryFile.delete();
                            pendingTransactionHistoryFile.createNewFile();
                        } catch (IOException e) {
                            logger.info("receiveAmount: Error reading clients file.");
                            return ActionLabel.FAIL.getLabel();
                        }
                    } else {
                        flag = false;
                        for (String[] t : pendingTransactionsSender) {
                            writeToCSV(senderPendingTransactionsFile, t, flag); //rewrite pending transaction of sender  file
                            flag = true;
                        }
                    }

                    writeToCSV(senderCompletedTransactionsFile, receiverTransaction, true);

                    // alter signature to that of this transaction
                    receiverTransaction[5] = signature;
                    writeToCSV(receiverTransactionsFile, receiverTransaction, true);

                }
            }

            return ActionLabel.COMPLETED_TRANSACTION.getLabel();
        } else {
            logger.info("receiveAmount: Sender/Receiver client not found!");
            return ActionLabel.CLIENT_NOT_FOUND.getLabel();
        }

    }

    private void createTransactionHistoryFiles(String username) {
        synchronized (bankVars.getClientLock(username)) {
            File completeTransactionHistoryFile = new File(this.name + "_csv_files/" + username + "_complete_transaction_history.csv");
            File pendingTransactionHistoryFile = new File(this.name + "_csv_files/" + username + "_pending_transaction_history.csv");
            if (!completeTransactionHistoryFile.exists()) {
                try {
                    completeTransactionHistoryFile.createNewFile();
                } catch (IOException e) {
                    logger.error("Error: ", e);
                }
            }
            if (!pendingTransactionHistoryFile.exists()) {
                try {
                    pendingTransactionHistoryFile.createNewFile();
                } catch (IOException e) {
                    logger.error("Error: ", e);
                }
            }
            try {
                completeTransactionHistoryFile.createNewFile();
                pendingTransactionHistoryFile.createNewFile();
            } catch (IOException e) {
                logger.error("Error: ", e);
            }
        }
    }

    public static void writeToCSV(String filePath, String[] values, boolean append) {
        try {
            FileWriter outputFile = new FileWriter(filePath, append);
            CSVWriter writer = new CSVWriter(outputFile, ',',
                    CSVWriter.NO_QUOTE_CHARACTER,
                    CSVWriter.DEFAULT_ESCAPE_CHARACTER,
                    CSVWriter.DEFAULT_LINE_END);
            writer.writeNext(values);
            writer.close();
        } catch (IOException e) {
            logger.error("Error: ", e);
        }
    }

    public PublicKey readPublic(String publicKeyPath) throws GeneralSecurityException, IOException {
        logger.info("Reading public key from file " + publicKeyPath + " ...");
        FileInputStream pubFis = new FileInputStream(publicKeyPath);
        byte[] pubEncoded = new byte[pubFis.available()];
        pubFis.read(pubEncoded);
        pubFis.close();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);

        return pub;
    }

    private int readTransactionIdAndIncrement() {
        //get current value
        int transactionId;
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (transactionIdFileLock) {
                fileReader = new FileReader(this.name + TRANSACTION_ID_FILE_PATH);
                reader = new BufferedReader(fileReader);
                String line = reader.readLine();
                transactionId = Integer.parseInt(line);
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("Error reading transaction id file.");
            return -1;
        }
        int newval = transactionId + 1;
        String[] valueStrings = new String[]{Integer.toString(newval)};
        writeToCSV(this.name + TRANSACTION_ID_FILE_PATH, valueStrings, false);
        return transactionId;
    }

    private void requestSign(String toSign, String username)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
        infoJson.addProperty("from", name);
        infoJson.addProperty("to", username);
        infoJson.addProperty("toSign", toSign);
        infoJson.addProperty("body", ActionLabel.SIGN.getLabel());
        infoJson.addProperty("requestId", Integer.toString(bankRequestId.get()));

        JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
        responseJson.add("info", infoJson);

        if (decryptCipher != null && msgDig != null) {
            decryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
            msgDig.update(infoJson.toString().getBytes());
            String ins = Base64.getEncoder().encodeToString(decryptCipher.doFinal(msgDig.digest()));
            responseJson.addProperty("MAC", ins);
        }

        logger.info("toSign Request: " + responseJson);

        // Send
        byte[] serverData = responseJson.toString().getBytes();
        logger.info(String.format("%d bytes %n", serverData.length));
        DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientAddress, clientPort);
        socket.send(serverPacket);
    }

    private String receiveAndCheckRequestSign()
            throws IOException, GeneralSecurityException {

        byte[] buf = new byte[BUFFER_SIZE];
        DatagramPacket Packet = new DatagramPacket(buf, buf.length);
        socket.setSoTimeout(SOCKET_TIMEOUT);

        try {
            socket.receive(Packet);
        } catch (SocketTimeoutException e) {
            logger.info("Socket timeout. Failed SignRequest!");
            logger.info("Socket closed");
            return ActionLabel.FAIL.getLabel();
        }

        logger.info("toSign Response: " + Packet);

        // Convert request to string
        String signInText = new String(Packet.getData(), 0, Packet.getLength());

        PublicKey pubClientKey = null;
        MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
        Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);
        Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

        // Parse JSON and extract arguments
        JsonObject requestJson = JsonParser.parseString(signInText).getAsJsonObject();
        String from, body, to, mac, requestId;

        JsonObject infoClientJson = requestJson.getAsJsonObject("info");
        to = infoClientJson.get("to").getAsString();
        from = infoClientJson.get("from").getAsString();
        body = infoClientJson.get("body").getAsString();
        requestId = infoClientJson.get("requestId").getAsString();
        mac = requestJson.get("MAC").getAsString();

        String publicClientPath = "keys/" + from + "_public_key.der";
        pubClientKey = readPublic(publicClientPath);
        decryptCipher.init(Cipher.DECRYPT_MODE, privKey);
        signCipher.init(Cipher.DECRYPT_MODE, pubClientKey);

        int idReceived = Integer.parseInt(requestId);

        String id;
        synchronized (requestIdFileLock) {
            id = getCurrentRequestIdFrom(from);
        }

        int ID = Integer.parseInt(id);

        if (idReceived <= ID) {
            logger.info("Message is duplicate, shall be ignored");
            return ActionLabel.FAIL.getLabel();
        } else if (ID == -1) {
            logger.error("Client has no request ID");
            return ActionLabel.FAIL.getLabel();
        } else if (idReceived != Integer.MAX_VALUE) { //valid request id
            synchronized (requestIdFileLock) {
                updateRequestID(from, requestId);
            }
        }

        byte[] macBytes;
        try {
            macBytes = signCipher.doFinal(Base64.getDecoder().decode(mac));
        } catch (Exception e) {
            logger.error("Error: ", e);
            logger.info("Entity not authenticated!");
            return ActionLabel.FAIL.getLabel();
        }
        msgDig.update(infoClientJson.toString().getBytes());
        if (Arrays.equals(macBytes, msgDig.digest())) {
            logger.info("Confirmed content integrity.");
        } else {
            logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes)));
            return ActionLabel.FAIL.getLabel();
        }

        int lastIndex = body.lastIndexOf(';');
        String sign = body.substring(lastIndex + 1);
        byte[] signBytes = sign.getBytes();
        String request = body.substring(0, lastIndex);

        byte[] requestBytes;
        try {
            requestBytes = signCipher.doFinal(Base64.getDecoder().decode(request));
        } catch (Exception e) {
            logger.error("Error: ", e);
            logger.info("Entity not authenticated!");
            return ActionLabel.FAIL.getLabel();
        }
        msgDig.update(signBytes);
        if (Arrays.equals(requestBytes, msgDig.digest())) {
            logger.info("Confirmed content integrity.");
        } else {
            logger.info(String.format("Recv: %s%nCalc: %s%n", Arrays.toString(msgDig.digest()), Arrays.toString(macBytes)));
            return ActionLabel.FAIL.getLabel();
        }

        writeToCSV(this.name + PENDING_TRANSACTION_SIGN_FILE_PATH, body.split(","), true);

        return ActionLabel.SUCCESS.getLabel();
    }

    private String handleWriteBackRequest(String body) {

        String[] transactions = body.split(";");

        String[] types = transactions[0].split(",");

        if (types[1].equals(ActionLabel.AUDITING.getLabel())) {
            if (transactions.length > 1) {
                redoClientsFile(transactions[1]);

                String from = transactions[1].split(",")[0];

                String path = this.name + "_csv_files/" + from + "_complete_transaction_history.csv";
                redoTransactionsFile(transactions, from, path);
            }

        } else if (types[1].equals(ActionLabel.CHECKING.getLabel())) {
            if (transactions.length > 1) {
                redoClientsFile(transactions[1]);

                String from = transactions[1].split(",")[0];

                String path = this.name + "_csv_files/" + from + "_pending_transaction_history.csv";
                redoTransactionsFile(transactions, from, path);
            }

        } else {
            return ActionLabel.FAIL.getLabel();
        }

        //can be any return, client will not check
        return ActionLabel.SUCCESS.getLabel();
    }

    public void redoClientsFile(String clientEntry) {

        System.out.println(clientEntry);

        String[] clientInfos = clientEntry.split(",");
        String clientName = clientInfos[0];
        String availableAmount = clientInfos[1];
        String bookAmount = clientInfos[2];

        //get account information
        String[] client;
        List<String[]> clients = new ArrayList<>();
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.name + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);
                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    clients.add(client);
                }
                fileReader.close();
                reader.close();
            }
        } catch (IOException e) {
            logger.info("receiveAmount: Error reading clients file.");
            return;
        }

        for (String[] c : clients) {
            if (c[0].equals(clientName)) {
                c[1] = availableAmount;
                c[2] = bookAmount;
                break;
            }
        }

        boolean flag = false;
        synchronized (clientsFileLock) {
            for (String[] c : clients) {
                writeToCSV(this.name + CLIENTS_CSV_FILE_PATH, c, flag);
                flag = true;
            }
        }
    }

    public void redoTransactionsFile(String[] transactions, String from, String path) {
        boolean flag = false;
        synchronized (bankVars.getClientLock(from)) {
            for (int i = 2; i < transactions.length; i++) {
                String[] transaction = transactions[i].split(",");
                writeToCSV(path, transaction, flag);
                flag = true;
            }
        }
    }
}