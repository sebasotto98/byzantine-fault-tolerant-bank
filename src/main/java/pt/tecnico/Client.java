package pt.tecnico;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.net.UnknownHostException;
import java.security.*;
import java.net.InetAddress;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Scanner;

public class Client {

    private static final String BANK_CONFIG_FILE = "config_files/banks.txt";

    private static final List<String> bankNames = new ArrayList<>();
    private static final List<Integer> bankPorts = new ArrayList<>();

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

    private static final int MAX_RETRIES = 5;

    private static final API api = new API();

    public static PublicKey readPublic(String publicKeyPath) throws GeneralSecurityException, IOException {
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

    public static PrivateKey readPrivate(String privateKeyPath) throws GeneralSecurityException, IOException {
        logger.info("Reading private key from file " + privateKeyPath + " ...");
        FileInputStream privFis = new FileInputStream(privateKeyPath);
        byte[] privEncoded = new byte[privFis.available()];
        privFis.read(privEncoded);
        privFis.close();

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

        return priv;
    }

    private static PrivateKey getPrivateKey(String username, Scanner sc) {
        PrivateKey pk = null;

        KeyStore ks;
        try {
            System.out.println("Please input alias for the keyStore entry.");
            String alias = sc.nextLine();
            System.out.println("Please input password for the keyStore.");
            String passwordString = sc.nextLine();

            String filePath = "ks/" + username + "_KeystoreFile.jks";
            FileInputStream fis = new FileInputStream(filePath);

            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, passwordString.toCharArray());
            fis.close();

            KeyStore.PasswordProtection password = new KeyStore.PasswordProtection(passwordString.toCharArray());
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, password);
            pk = pkEntry.getPrivateKey();

        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            logger.error("Error: ", e);
        }

        return pk;
    }

    private static void savePrivateKey(PrivateKey privateKey, String username, Scanner sc, String alias, String passwordString) {
        KeyStore ks;
        try {

            String filePath = "ks/" + username + "_KeystoreFile.jks";
            FileInputStream fis = new FileInputStream(filePath);
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, passwordString.toCharArray());
            fis.close();

            KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(privateKey, ks.getCertificateChain(alias));
            KeyStore.PasswordProtection password = new KeyStore.PasswordProtection(passwordString.toCharArray());

            ks.setEntry(alias, pkEntry, password);
            FileOutputStream fos = new FileOutputStream(filePath);
            ks.store(fos, passwordString.toCharArray());
            fos.close();

            System.out.println("Private Key of " + username + " stored.");

        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            logger.error("Error: ", e);
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            return;
        }
        readConfig();

        final int myPort = Integer.parseInt(args[0]);

        InetAddress bankAddress = null;
        try {
            bankAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            logger.error("Error: ", e);
        }

        Scanner sc = new Scanner(System.in);
        showMainMenu(myPort, bankAddress, sc);
    }

    private static void showMainMenu(int myPort, InetAddress bankAddress, Scanner sc) {
        int ch;
        while (true) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Log in \n3. Exit \n ");
            System.out.println("Please enter your choice: ");
            try {
                ch = sc.nextInt();
                sc.nextLine();//flush
            }  catch (InputMismatchException ex) { // force an integer
                ch = -1;
                sc.nextLine();//flush
            }
            switch (ch) {
                case 1:
                    handleOpenAccount(myPort, bankAddress, sc);
                    break;
                case 2:
                    System.out.println("Please input your username.");
                    String username = sc.nextLine();
                    PrivateKey privateKey = getPrivateKey(username, sc);
                    if (privateKey != null) {
                        try {
                            String requestedID = "-1";
                            for(int i = 0; i < bankPorts.size(); i++) {
                                PublicKey bankPublicKey = null;
                                try {
                                    bankPublicKey = readPublic("keys/" + bankNames.get(i) + "_public_key.der");
                                } catch (GeneralSecurityException | IOException e) {
                                    logger.error("Error: ", e);
                                }
                                if(bankPublicKey != null) {
                                    requestedID = api.setInitialRequestIDs(privateKey, myPort, bankPorts.get(i), bankAddress,
                                            bankPublicKey, username, Integer.MAX_VALUE, bankNames.get(i));
                                }
                            }
                            if(!requestedID.equals("-1") && !requestedID.equals(ActionLabel.FAIL.getLabel())) {
                                showSubmenu(sc, myPort, bankAddress, privateKey, username, Integer.parseInt(requestedID) + 1);
                            } else {
                                logger.info("RequestID invalid or Fail.");
                                System.out.println("Impossible to log in.");
                            }
                        } catch (GeneralSecurityException | IOException e) {
                            logger.error("Error: ", e);
                        }
                    } else {
                        logger.info("Private key is null.");
                        System.out.println("Impossible to log in.");
                    }
                    break;
                case 3:
                    System.out.println("Thank you for using BFTB.");
                    return;
                default:
                    System.out.println("Please enter a valid option.");
            }
        }
    }

    public static void showSubmenu(Scanner sc, int myPort, InetAddress bankAddress,
                                   PrivateKey privateKey, String username, int requestID) {
        int ch;
        while (true) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Send amount \n2. Check account \n3. Receive amount \n4. Audit account \n5. Log out ");
            System.out.println("Please enter your choice: ");
            try {
                ch = sc.nextInt();
                sc.nextLine();
            }  catch (InputMismatchException ex) { // force an integer
                ch = -1;
                sc.nextLine();
            }
            switch (ch) {
                case 1:
                    requestID = handleSendAmount(myPort, bankAddress, requestID, sc, privateKey, username);
                    break;
                case 2:
                    requestID = handleCheckAccount(myPort, bankAddress, requestID, sc, privateKey, username);
                    break;
                case 3:
                    requestID = handleReceiveAmount(myPort, bankAddress, requestID, sc, privateKey, username);
                    break;
                case 4:
                    requestID = handleAuditAccount(myPort, bankAddress, requestID, sc, privateKey, username);
                    break;
                case 5:
                    return;
                default:
                    System.out.println("Please enter a valid option.");
            }
        }
    }

    private static int handleAuditAccount(int myPort, InetAddress bankAddress, int requestID,
                                          Scanner sc, PrivateKey privateKey, String username) {
        String bankResponse;
        try {
            System.out.println("Please input username of the account's owner (to fetch public key).");
            String owner = sc.nextLine();
            int numberOfTries = 0;
            for(int h = 0; h < bankPorts.size(); h++) {

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(h) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                do {
                    bankResponse = api.auditAccount(privateKey, myPort, bankPorts.get(h), bankAddress, bankNames.get(h), bankPublicKey, username, requestID, owner);
                    if (bankResponse != null) {
                        if (bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())) {
                            System.out.println("Owner's account not found!");
                        } else if (bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                            System.out.println("Error trying to read clients file or owner's pending transactions file.");
                        } else {
                            System.out.println("Account details: ");
                            String[] messages = bankResponse.split(";");
                            String[] accountDetails = messages[0].split(",");
                            System.out.println("-Owner: " + accountDetails[0]);
                            System.out.println("-Available amount: " + accountDetails[1]);
                            System.out.println("-Book amount: " + accountDetails[2]);
                            System.out.println("Complete transactions associated with the account: ");
                            for (int i = 1; i < messages.length; i++) {
                                String[] s = messages[i].split(",");

                                String str = "ID: " +
                                        s[0] +
                                        ". At " +
                                        s[1] +
                                        " user " +
                                        s[2] +
                                        " sent " +
                                        s[4] +
                                        " euros to user " +
                                        s[3] +
                                        ". Transaction accepted.";
                                System.out.println(str);
                            }
                        }
                    } else {
                        bankResponse = ActionLabel.FAIL.getLabel();
                    }
                    numberOfTries++;
                } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
                numberOfTries = 0;
            }

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID + 1;
    }

    private static int handleReceiveAmount(int myPort, InetAddress bankAddress, int requestID,
                                           Scanner sc, PrivateKey privateKey, String username) {

        String bankResponse;

        try {
            System.out.println("Which transaction do you wish to complete?");
            int transactionId = sc.nextInt();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            for(int i = 0; i < bankPorts.size(); i++) {

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(i) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                do {
                    bankResponse = api.receiveAmount(privateKey, myPort, bankPorts.get(i), bankAddress, bankNames.get(i), bankPublicKey, username, requestID, transactionId);
                    if (bankResponse != null) {
                        if (bankResponse.equals(ActionLabel.COMPLETED_TRANSACTION.getLabel())) {
                            System.out.println("Transaction completed and money transfered!");
                        } else if (bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                            System.out.println("Failed to send amount. An error occurred.");
                        } else if (bankResponse.equals(ActionLabel.CLIENT_NOT_RECEIVER.getLabel())) {
                            System.out.println("You are not the receiver for that transfer.");
                        } else if (bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())) {
                            System.out.println("Sender/Receiver account not found!");
                        }
                    } else {
                        bankResponse = ActionLabel.FAIL.getLabel();
                    }
                    numberOfTries++;
                } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
                numberOfTries = 0;
            }

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID + 1;
    }

    private static int handleCheckAccount(int myPort, InetAddress bankAddress, int requestID,
                                          Scanner sc, PrivateKey privateKey, String username) {
        String bankResponse;
        try {

            System.out.println("Please input username of the account's owner (to fetch public key).");
            String owner = sc.nextLine();

            int numberOfTries = 0;
            for(int h = 0; h < bankPorts.size(); h++) {

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(h) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                do {
                    bankResponse = api.checkAccount(privateKey, myPort, bankPorts.get(h), bankAddress, bankNames.get(h), bankPublicKey, username, requestID, owner);
                    if (bankResponse != null) {
                        if (bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())) {
                            System.out.println("Owner's account not found!");
                        } else if (bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                            System.out.println("Error trying to read clients file or owner's pending transactions file.");
                        } else {
                            System.out.println("Account details: ");
                            String[] messages = bankResponse.split(";");
                            String[] accountDetails = messages[0].split(",");
                            System.out.println("-Owner: " + accountDetails[0]);
                            System.out.println("-Available amount: " + accountDetails[1]);
                            System.out.println("-Book amount: " + accountDetails[2]);
                            System.out.println("Pending transactions associated with the account: ");
                            for (int i = 1; i < messages.length; i++) {
                                String[] s = messages[i].split(",");

                                String str = "ID: " +
                                        s[0] +
                                        ". At " +
                                        s[1] +
                                        " user " +
                                        s[2] +
                                        " sent " +
                                        s[4] +
                                        " euros to user " +
                                        s[3] +
                                        ". Transaction waiting approval.";
                                System.out.println(str);
                            }
                        }
                    } else {
                        bankResponse = ActionLabel.FAIL.getLabel();
                    }
                    numberOfTries++;
                } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
                numberOfTries = 0;
            }

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }

        return requestID + 1;
    }

    private static int handleSendAmount(int myPort, InetAddress bankAddress, int requestID,
                                        Scanner sc, PrivateKey privateKey, String username) {

        String bankResponse;
        try {

            System.out.println("Please input username of receiver account (to fetch public key).");
            String usernameDest = sc.nextLine();

            System.out.println("How much do you want to transfer?");
            float amount = sc.nextFloat();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            for(int i = 0; i < bankPorts.size(); i++) {

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(i) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                do {
                    bankResponse = api.sendAmount(privateKey, myPort, bankPorts.get(i), bankAddress, bankNames.get(i), bankPublicKey, requestID, username, amount, usernameDest);
                    if (bankResponse != null) {
                        if (bankResponse.equals(ActionLabel.PENDING_TRANSACTION.getLabel())) {
                            System.out.println("Transaction waiting for receiver approval!");
                        } else if (bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                            System.out.println("Failed to send amount. An error occurred.");
                        } else if (bankResponse.equals(ActionLabel.NEGATIVE_AMOUNT.getLabel())) {
                            System.out.println("Not possible to send negative amount!");
                        } else if (bankResponse.equals(ActionLabel.INSUFFICIENT_AMOUNT.getLabel())) {
                            System.out.println("Insufficient available amount on sender account.");
                        } else if (bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())) {
                            System.out.println("Sender/Receiver client not found or trying to send money to self!");
                        }
                    } else {
                        bankResponse = ActionLabel.FAIL.getLabel();
                    }
                    numberOfTries++;
                } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
                numberOfTries = 0;
            }
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID + 1;
    }

    private static void handleOpenAccount(int myPort, InetAddress bankAddress, Scanner sc) {

        String bankResponse = "";
        String username;
        String privateKeyPath;
        PrivateKey privateKey;
        System.out.println("Please input your username (to fetch public and private key).");
        username = sc.nextLine();

        privateKeyPath = "keys/" + username + "_private_key.der";

        System.out.println("Please input alias for the keyStore entry.");
        String alias = sc.nextLine();
        System.out.println("Please input password for the keyStore.");
        String passwordString = sc.nextLine();

        try {
            privateKey = readPrivate(privateKeyPath);
            int numberOfTries = 0;
            for(int i = 0; i < bankPorts.size(); i++) {

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(i) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                do {
                    bankResponse = api.openAccount(privateKey, myPort, bankPorts.get(i), bankAddress, bankPublicKey, username, -1, bankNames.get(i));
                    if (bankResponse != null) {
                        if (bankResponse.equals(ActionLabel.ACCOUNT_CREATED.getLabel())) {
                            System.out.println("Account opened successfully!");
                            savePrivateKey(privateKey, username, sc, alias, passwordString);
                        } else if (bankResponse.equals(ActionLabel.DUPLICATE_USERNAME.getLabel())) {
                            System.out.println("Client " + username + " already has an account.");
                        } else if (bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                            System.out.println("Failed to open account.");
                        }
                    } else {
                        bankResponse = ActionLabel.FAIL.getLabel();
                    }

                    numberOfTries++;
                } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
                numberOfTries = 0;
            }
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        privateKey = null;
    }

    private static void readConfig(){
        FileReader fileReader;
        BufferedReader reader;
        String[] infos;
        try {
            fileReader = new FileReader(BANK_CONFIG_FILE);
            reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                infos = line.split(",");
                bankNames.add(infos[0]);
                bankPorts.add(Integer.parseInt(infos[1]));
            }
            fileReader.close();
            reader.close();
        } catch (IOException e) {
            logger.info("openAccount: Error reading requestId file.");
        }
    }
}