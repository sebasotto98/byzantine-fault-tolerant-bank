package pt.tecnico;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.invoke.MethodHandles;
import java.net.UnknownHostException;
import java.security.*;
import java.io.IOException;
import java.net.InetAddress;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {

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

    private static PrivateKey getPrivateKey(String username, Scanner sc){
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
        if (args.length < 3) {
            System.err.println("Argument(s) missing!");
            return;
        }
        final int port = Integer.parseInt(args[0]);
        final int bankPort = Integer.parseInt(args[1]);
        final String bankName = args[2];
        InetAddress bankAddress = null;
        try {
            bankAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            logger.error("Error: ", e);
        }
        int requestID = 0;
        PublicKey bankPublicKey = null;
        try {
            bankPublicKey = readPublic("keys/" + bankName + "_public_key.der");
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        Scanner sc = new Scanner(System.in);
        int ch = 0;

        //main menu
        while (true) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Log in \n3. Exit \n ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            sc.nextLine();//flush
            switch (ch) {
                case 1:
                    handleOpenAccount(port, bankPort, bankAddress, bankName, bankPublicKey, sc);
                    break;
                case 2:
                    System.out.println("Please input your username.");
                    String username = sc.nextLine();
                    PrivateKey privateKey = getPrivateKey(username, sc);
                    if(privateKey != null){
                        try {
                            //initial ID request with max_value
                            String[] requestedIDS = api.requestIDs(privateKey, port, bankPort, bankAddress,
                                    bankPublicKey, username, Integer.MAX_VALUE, bankName);

                            submenu(sc, port, bankPort, bankAddress, bankPublicKey, bankName, privateKey,
                                    username, Integer.parseInt(requestedIDS[0]) + 1);
                            privateKey = null;
                        } catch (GeneralSecurityException | IOException e) {
                            logger.error("Error: ", e);
                        }
                    } else {
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

    public static void submenu(Scanner sc, int port, int bankPort,  InetAddress bankAddress,
                               PublicKey bankPublicKey, String bankName,
                               PrivateKey privateKey, String username, int requestID){

        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Send amount \n2. Check account \n3. Receive amount \n4. Audit account \n5. Log out ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            sc.nextLine();//flush
            switch (ch) {
                case 1:
                    requestID = handleSendAmount(port, bankPort, bankAddress, requestID, bankPublicKey, sc, bankName, privateKey, username);
                    break;
                case 2:
                    requestID = handleCheckAccount(port, bankPort, bankAddress, requestID, bankPublicKey, sc, bankName, privateKey, username);
                    break;
                case 3:
                    requestID = handleReceiveAmount(port, bankPort, bankAddress, requestID, bankPublicKey, sc, bankName, privateKey, username);
                    break;
                case 4:
                    requestID = handleAuditAccount(port, bankPort, bankAddress, requestID, bankPublicKey, sc, bankName, privateKey, username);
                    break;
                case 5:
                    return;
                default:
                    System.out.println("Please enter a valid option.");
            }
        }
    }

    private static int handleAuditAccount(int port, int bankPort, InetAddress bankAddress, int requestID,
                                          PublicKey bankPublicKey, Scanner sc, String bankName,
                                          PrivateKey privateKey, String username) {
        String bankResponse;
        try {
            System.out.println("Please input username of the account's owner (to fetch public key).");
            String owner = sc.nextLine();

            int numberOfTries = 0;
            do {
                bankResponse = api.auditAccount(privateKey, port, bankPort, bankAddress, bankName, bankPublicKey, username, requestID, owner);
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
            requestID++;

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID;
    }

    private static int handleReceiveAmount(int port, int bankPort, InetAddress bankAddress, int requestID,
                                           PublicKey bankPublicKey, Scanner sc, String bankName,
                                           PrivateKey privateKey, String username) {

        String bankResponse;

        try {
            System.out.println("Which transaction do you wish to complete?");
            int transactionId = sc.nextInt();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            do {
                bankResponse = api.receiveAmount(privateKey, port, bankPort, bankAddress, bankName, bankPublicKey, username, requestID, transactionId);
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
            requestID++;

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID;
    }

    private static int handleCheckAccount(int port, int bankPort, InetAddress bankAddress, int requestID,
                                          PublicKey bankPublicKey, Scanner sc, String bankName,
                                          PrivateKey privateKey, String username) {
        String bankResponse;
        try {

            System.out.println("Please input username of the account's owner (to fetch public key).");
            String owner = sc.nextLine();

            int numberOfTries = 0;
            do {
                bankResponse = api.checkAccount(privateKey, port, bankPort, bankAddress, bankName, bankPublicKey, username, requestID, owner);
                if(bankResponse != null) {
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
            } while((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
            requestID++;

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }

        return requestID;
    }

    private static int handleSendAmount(int port, int bankPort, InetAddress bankAddress, int requestID,
                                        PublicKey bankPublicKey, Scanner sc, String bankName,
                                        PrivateKey privateKey, String username) {

        String bankResponse;
        try {

            System.out.println("Please input username of receiver account (to fetch public key).");
            String usernameDest = sc.nextLine();

            System.out.println("How much do you want to transfer?");
            float amount = sc.nextFloat();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            do {
                bankResponse = api.sendAmount(privateKey, port, bankPort, bankAddress, bankName, bankPublicKey, requestID, username, amount, usernameDest);
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
                        System.out.println("Sender/Receiver account not found!");
                    }
                } else {
                    bankResponse = ActionLabel.FAIL.getLabel();
                }
                numberOfTries++;
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);
            requestID++;

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID;
    }

    private static void handleOpenAccount(int port, int bankPort, InetAddress bankAddress, String bankName,
                                          PublicKey bankPublicKey, Scanner sc) {

        String bankResponse;
        String username;
        String privateKeyPath;
        PrivateKey privateKey;
        System.out.println("Please input your username (to fetch public and private key).");
        username = sc.nextLine();

        privateKeyPath = "keys/"+username+"_private_key.der";

        //only used if success
        System.out.println("Please input alias for the keyStore entry.");
        String alias = sc.nextLine();
        System.out.println("Please input password for the keyStore.");
        String passwordString = sc.nextLine();

        try {
            privateKey = readPrivate(privateKeyPath);
            int numberOfTries = 0;
            do {
                bankResponse = api.openAccount(privateKey, port, bankPort, bankAddress, bankPublicKey, username, -1, bankName);
                if(bankResponse != null) {
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
            } while((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_RETRIES);

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        privateKey = null;
    }
}
