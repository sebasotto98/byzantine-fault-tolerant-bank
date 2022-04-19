package pt.tecnico;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opencsv.CSVWriter;
import org.slf4j.Logger;

import javax.crypto.Cipher;
import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class WorkerThread extends Thread {

    private static final int INITIAL_ACCOUNT_BALANCE = 1000;

    private static final String DIGEST_ALGO = "SHA-256";
    private static final String CIPHER_ALGO = "RSA/ECB/PKCS1Padding";
    private static final String CLIENTS_CSV_FILE_PATH = "_csv_files/clients.csv";
    private static final String REQUEST_ID_CSV_FILE_PATH = "_csv_files/requestIDs.csv";
    private static final String SIGNATURES_CSV_FILE_PATH = "_csv_files/signatures.csv";

    private final DatagramPacket clientPacket;

    private final Logger logger;

    private final String NAME;
    private final Cipher DecryptCipher;
    private final MessageDigest msgDig;
    private final PrivateKey privKey;
    private final AtomicInteger bankRequestId;
    private final SharedBankVars bankVars;

    private final DatagramSocket socket;

    private final Object clientsFileLock;
    private final Object requestIdFileLock;
    private final Object signaturesFileLock;

    public WorkerThread(int socketPort, DatagramPacket clientPacket, Logger logger, String name,
                        Cipher DecryptCipher, MessageDigest msgDig, PrivateKey privKey,
                        SharedBankVars bankVars) throws SocketException {

        this.bankVars = bankVars;

        this.clientPacket = clientPacket;

        this.DecryptCipher = DecryptCipher;
        this.msgDig = msgDig;
        this.privKey = privKey;

        this.logger = logger;
        this.NAME = name;

        this.bankRequestId = this.bankVars.getBankRequestId();

        this.clientsFileLock = this.bankVars.getClientsFileLock();
        this.requestIdFileLock = this.bankVars.getRequestIdFileLock();
        this.signaturesFileLock = this.bankVars.getSignaturesFileLock();

        this.socket = new DatagramSocket(socketPort);
    }

    @Override
    public void run() {
        try {
            System.out.println("I AM THREAD " + Thread.currentThread().getId());
            InetAddress clientAddress = clientPacket.getAddress();
            int clientPort = clientPacket.getPort();
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
            infoJson.addProperty("from", NAME);
            infoJson.addProperty("to", response[1]);
            infoJson.addProperty("requestId", Integer.toString(bankRequestId.get()));
            infoJson.addProperty("body", response[0]);

            bankVars.incrementBankRequestID();

            responseJson.add("info", infoJson);

            if (DecryptCipher != null && msgDig != null) {
                DecryptCipher.init(Cipher.ENCRYPT_MODE, privKey);
                msgDig.update(infoJson.toString().getBytes());
                String ins = Base64.getEncoder().encodeToString(DecryptCipher.doFinal(msgDig.digest()));
                responseJson.addProperty("MAC", ins);
                synchronized (signaturesFileLock) {
                    //Store signature
                    writeToCSV(this.NAME + SIGNATURES_CSV_FILE_PATH, new String[]{NAME, response[1], ins}, true);
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
        String[] response = new String[2];

        PublicKey pubClientKey = null;
        MessageDigest msgDig = MessageDigest.getInstance(DIGEST_ALGO);
        Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGO);
        Cipher signCipher = Cipher.getInstance(CIPHER_ALGO);

        // Parse JSON and extract arguments
        JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
        String from, body, to, mac, requestId;

        JsonObject infoClientJson = requestJson.getAsJsonObject("info");
        to = infoClientJson.get("to").getAsString();
        from = infoClientJson.get("from").getAsString();
        body = infoClientJson.get("body").getAsString();
        requestId = infoClientJson.get("requestId").getAsString();
        mac = requestJson.get("MAC").getAsString();

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

        int ID = Integer.parseInt(id);

        if (idReceived <= ID) {
            logger.info("Message is duplicate, shall be ignored");
            response[0] = ActionLabel.FAIL.getLabel();
        } else if (ID == -1) {
            logger.error("Client has no request ID");
            response[0] = ActionLabel.FAIL.getLabel();
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
            writeToCSV(this.NAME + SIGNATURES_CSV_FILE_PATH, new String[]{from, NAME, mac}, true);
        }

        response[0] = setResponse(bodyArray, from);
        response[1] = from;

        logger.info(String.format("Message to '%s', from '%s':%n%s%n", to, from, body));
        logger.info("response body = " + response[0]);

        return response;
    }

    private String getCurrentRequestIdFrom(String username) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client;
        try {
            fileReader = new FileReader(this.NAME + REQUEST_ID_CSV_FILE_PATH);
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
            logger.info("openAccount: Error reading requestId file.");
        }
        return "-1";
    }

    private void updateRequestID(String username, String requestID) {
        //get list of clients
        FileReader fileReader;
        BufferedReader reader;
        String[] client;
        List<String[]> clients = new ArrayList<>();
        try {
            fileReader = new FileReader(this.NAME + REQUEST_ID_CSV_FILE_PATH);
            reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                client = line.split(",");
                clients.add(client);
            }
            fileReader.close();
            reader.close();
        } catch (IOException e) {
            logger.info("openAccount: Error reading requestId file.");
        }

        for (String[] c : clients) {
            if (c[0].equals(username)) {
                c[1] = requestID;
                break;
            }
        }
        boolean flag = false;
        for (String[] c : clients) {
            writeToCSV(this.NAME + REQUEST_ID_CSV_FILE_PATH, c, flag);
            flag = true;
        }
    }

    private String setResponse(String[] bodyArray, String username) {
        //bodyArray -> 1-amount, 2-receiver
        if (bodyArray[0].equals(ActionLabel.OPEN_ACCOUNT.getLabel())) {
            return handleOpenAccount(username);
        } else if (bodyArray[0].equals(ActionLabel.SEND_AMOUNT.getLabel())) {
            return handleSendAmountRequest(username, bodyArray[1], bodyArray[2]);
        } else if (bodyArray[0].equals(ActionLabel.CHECK_ACCOUNT.getLabel())) {
            return handleCheckAccountRequest(bodyArray[1]);
        } else if (bodyArray[0].equals(ActionLabel.RECEIVE_AMOUNT.getLabel())) {
            return handleReceiveAmountRequest(username, bodyArray[1]);
        } else if (bodyArray[0].equals(ActionLabel.AUDIT_ACCOUNT.getLabel())) {
            return handleAuditAccountRequest(bodyArray[1]);
        } else if (bodyArray[0].equals(ActionLabel.REQUEST_MY_ID.getLabel())) {
            synchronized (requestIdFileLock) {
                return getCurrentRequestIdFrom(username);
            }
        } else if (bodyArray[0].equals(ActionLabel.REQUEST_BANK_ID.getLabel())) {
            return String.valueOf(bankRequestId);
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
                fileReader = new FileReader(this.NAME + CLIENTS_CSV_FILE_PATH);
                reader = new BufferedReader(fileReader);

                String line;
                while ((line = reader.readLine()) != null) {
                    client = line.split(",");
                    if (client[0].equals(username)) {
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
            writeToCSV(this.NAME + CLIENTS_CSV_FILE_PATH, new String[]{username, Integer.toString(INITIAL_ACCOUNT_BALANCE),
                    Integer.toString(INITIAL_ACCOUNT_BALANCE)}, true);
        }

        createTransactionHistoryFiles(username);

        synchronized (requestIdFileLock) {
            writeToCSV(this.NAME + REQUEST_ID_CSV_FILE_PATH, new String[]{username, Integer.toString(0)}, true);
        }
        return ActionLabel.ACCOUNT_CREATED.getLabel();
    }

    private String handleAuditAccountRequest(String owner) {
        FileReader fileReader;
        BufferedReader reader;
        String[] client = null;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.NAME + CLIENTS_CSV_FILE_PATH);
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
            String ownerPendingTransactionsPath = this.NAME + "_csv_files/" + owner + "_complete_transaction_history.csv";
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
                fileReader = new FileReader(this.NAME + CLIENTS_CSV_FILE_PATH);
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
            String ownerPendingTransactionsPath = this.NAME + "_csv_files/" + owner + "_pending_transaction_history.csv";
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

    private String handleSendAmountRequest(String username, String amount, String receiver) {
        //get account information
        String[] client;
        List<String[]> clients = new ArrayList<>();
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.NAME + CLIENTS_CSV_FILE_PATH);
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
                    writeToCSV(this.NAME + CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
                    flag = true;
                }
            }

            String receiverPendingTransactionsFile = this.NAME + "_csv_files/" + receiver + "_pending_transaction_history.csv";
            String senderPendingTransactionsFile = this.NAME + "_csv_files/" + username + "_pending_transaction_history.csv";

            String[] transaction = new String[5];
            transaction[0] = String.valueOf(bankVars.getTransactionId());
            transaction[1] = new Timestamp(System.currentTimeMillis()).toString();
            transaction[2] = username;
            transaction[3] = receiver;
            transaction[4] = amount;

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

    private String handleReceiveAmountRequest(String username, String id) {

        //get account information
        String[] client;
        List<String[]> clients = new ArrayList<>();
        FileReader fileReader;
        BufferedReader reader;
        try {
            synchronized (clientsFileLock) {
                fileReader = new FileReader(this.NAME + CLIENTS_CSV_FILE_PATH);
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
            System.out.println("sendAmount: Error reading clients file.");
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
        String usernamePendingTransactionsPath = this.NAME + "_csv_files/" + username + "_pending_transaction_history.csv";
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
            System.out.println("sendAmount: Error reading clients file.");
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
                //c -> 0-id, 1-timestamp, 2-sender 3-receiver 4-amount
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
                    writeToCSV(this.NAME + CLIENTS_CSV_FILE_PATH, c, flag); //rewrite clients file
                    flag = true;
                }
            }

            // updating transactions in
            String[] pendingTransactionSender;
            String usernamePendingTransactionsSenderPath = this.NAME + "_csv_files/" + sender + "_pending_transaction_history.csv";
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
                System.out.println("sendAmount: Error reading clients file.");
                return ActionLabel.FAIL.getLabel();
            }

            pendingTransactions.remove(receiverTransaction);
            pendingTransactionsSender.remove(transactionInSender);

            String receiverPendingTransactionsFile = this.NAME + "_csv_files/" + username + "_pending_transaction_history.csv";
            String receiverTransactionsFile = this.NAME + "_csv_files/" + username + "_complete_transaction_history.csv";
            String senderPendingTransactionsFile = this.NAME + "_csv_files/" + sender + "_pending_transaction_history.csv";
            String senderCompletedTransactionsFile = this.NAME + "_csv_files/" + sender + "_complete_transaction_history.csv";

            System.out.println("Receiver pending " + pendingTransactions.size() + "; sender pending " + pendingTransactionsSender.size());
            System.out.println("");
            System.out.println("");
            System.out.println("");
            System.out.println("");

            synchronized (bankVars.getClientLock(username)) {
                synchronized (bankVars.getClientLock(sender)) {
                    if (pendingTransactions.size() == 0) {
                        // clear all contents of file
                        try {
                            File pendingTransactionHistoryFile = new File(this.NAME + "_csv_files/" + username + "_pending_transaction_history.csv");
                            pendingTransactionHistoryFile.delete();
                            pendingTransactionHistoryFile.createNewFile();
                        } catch (IOException e) {
                            System.out.println("sendAmount: Error reading clients file.");
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
                            File pendingTransactionHistoryFile = new File(this.NAME + "_csv_files/" + sender + "_pending_transaction_history.csv");
                            pendingTransactionHistoryFile.delete();
                            pendingTransactionHistoryFile.createNewFile();
                        } catch (IOException e) {
                            System.out.println("sendAmount: Error reading clients file.");
                            return ActionLabel.FAIL.getLabel();
                        }
                    } else {
                        flag = false;
                        for (String[] t : pendingTransactionsSender) {
                            writeToCSV(senderPendingTransactionsFile, t, flag); //rewrite pending transaction of sender  file
                            flag = true;
                        }
                    }

                    writeToCSV(receiverTransactionsFile, receiverTransaction, true);
                    writeToCSV(senderCompletedTransactionsFile, receiverTransaction, true);
                }
            }

            return ActionLabel.COMPLETED_TRANSACTION.getLabel();
        } else {
            System.out.println("sendAmount: Sender/Receiver client not found!");
            return ActionLabel.CLIENT_NOT_FOUND.getLabel();
        }

    }

    private void createTransactionHistoryFiles(String username) {
        synchronized (bankVars.getClientLock(username)) {
            File completeTransactionHistoryFile = new File(this.NAME + "_csv_files/" + username + "_complete_transaction_history.csv");
            File pendingTransactionHistoryFile = new File(this.NAME + "_csv_files/" + username + "_pending_transaction_history.csv");
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

    private void writeToCSV(String filePath, String[] values, boolean append) {
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
}