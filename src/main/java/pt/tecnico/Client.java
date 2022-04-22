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
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Client {

    private static API api;

    private static final String BANK_CONFIG_FILE = "config_files/banks.txt";
    private static final String INPUT_CHARACTER_VALIDATION = "^[a-zA-Z0-9]*$";
    private static final String INPUT_LENGTH_VALIDATION = "^(.{4,20})";

    private static final List<String> bankNames = new ArrayList<>();
    private static final List<Integer> bankPorts = new ArrayList<>();

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass().getSimpleName());

    private static final int MAX_REQUEST_RETRIES = 5;

    private static final Map<String, String> puzzles;
    static {
        puzzles = new HashMap<>();
        puzzles.put("How much is 2+2?", "4");
        puzzles.put("What is the capital of Portugal?", "Lisbon");
        puzzles.put("How many days in January?", "31");
    }

    private static int replicas;
    private static int faults;

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
            while(!isRegularInput(alias, false)) {
                System.out.println("Please enter a valid alias.");
                alias = sc.nextLine();
            }
            System.out.println("Please input password for the keyStore.");
            String passwordString = sc.nextLine();
            while(!isRegularInput(passwordString, true)) {
                System.out.println("Please enter a valid password.");
                passwordString = sc.nextLine();
            }

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
        readConfig();

        final int myPort = Integer.parseInt(args[0]);
        replicas = Integer.parseInt(args[1]);
        faults = Integer.parseInt(args[2]);

        api = new API(bankNames, bankPorts, faults);

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
            } catch (InputMismatchException ex) { // force an integer
                ch = -1;
                sc.nextLine();//flush
            }
            switch (ch) {
                case 1:
                    if(solveRandomPuzzle(sc)) {
                        handleOpenAccount(myPort, bankAddress, sc);
                    }
                    break;
                case 2:
                    if(solveRandomPuzzle(sc)) {
                        handleLogin(myPort, bankAddress, sc);
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

    private static void handleLogin(int myPort, InetAddress bankAddress, Scanner sc) {
        System.out.println("Please input your username.");
        String username = sc.nextLine();
        while(!isRegularInput(username, false)) {
            System.out.println("Please enter a valid username.");
            username = sc.nextLine();
        }
        PrivateKey privateKey = getPrivateKey(username, sc);
        if (privateKey != null) {
            try {
                String requestedID = "-1";

                PublicKey bankPublicKey = null;
                try {
                    bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
                } catch (GeneralSecurityException | IOException e) {
                    logger.error("Error: ", e);
                }
                if (bankPublicKey != null) {
                    requestedID = api.setInitialRequestIDs(privateKey, myPort, bankPorts.get(0), bankAddress,
                            bankPublicKey, username, Integer.MAX_VALUE, bankNames.get(0));
                }

                if (!requestedID.equals("-1") && !requestedID.equals(ActionLabel.FAIL.getLabel())) {
                    showSubmenu(sc, myPort, bankAddress, privateKey, username, Integer.parseInt(requestedID) + 1);
                } else {
                    logger.info("RequestID invalid or Fail.");
                    System.out.println("Login failed.");
                }
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
            }
        } else {
            logger.info("Private key is null.");
            System.out.println("Impossible to log in.");
        }
    }

    private static void showSubmenu(Scanner sc, int myPort, InetAddress bankAddress,
                                   PrivateKey privateKey, String username, int requestID) {
        System.out.println("Welcome " + username);
        int ch;
        while (true) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Send amount \n2. Check account \n3. Receive amount \n4. Audit account \n5. Log out ");
            System.out.println("Please enter your choice: ");
            try {
                ch = sc.nextInt();
                sc.nextLine();
            } catch (InputMismatchException ex) { // force an integer
                ch = -1;
                sc.nextLine();
            }
            switch (ch) {
                case 1:
                    if(solveRandomPuzzle(sc)) {
                        requestID = handleSendAmount(myPort, bankAddress, requestID, sc, privateKey, username);
                    }
                    break;
                case 2:
                    if(solveRandomPuzzle(sc)) {
                        requestID = handleCheckAccount(myPort, bankAddress, requestID, sc, privateKey, username);
                    }
                    break;
                case 3:
                    if(solveRandomPuzzle(sc)) {
                        requestID = handleReceiveAmount(myPort, bankAddress, requestID, sc, privateKey, username);
                    }
                    break;
                case 4:
                    if(solveRandomPuzzle(sc)) {
                        requestID = handleAuditAccount(myPort, bankAddress, requestID, sc, privateKey, username);
                    }
                    break;
                case 5:
                    System.out.println(requestID);
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
            while(!isRegularInput(username, false)) {
                System.out.println("Please enter a valid username.");
                username = sc.nextLine();
            }
            int numberOfTries = 0;

            PublicKey bankPublicKey = null;
            try {
                bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
            }
            do {
                bankResponse = api.auditAccount(privateKey, myPort, bankPorts.get(0), bankAddress, bankNames.get(0), bankPublicKey, username, requestID, owner);
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
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_REQUEST_RETRIES);
            numberOfTries = 0;

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        return requestID + 2;
    }

    private static int handleReceiveAmount(int myPort, InetAddress bankAddress, int requestID,
                                           Scanner sc, PrivateKey privateKey, String username) {

        String bankResponse;

        try {
            System.out.println("Which transaction do you wish to complete?");
            boolean hasInt = sc.hasNextInt();
            while(!hasInt) {
                System.out.println("Please input a transaction number.");
                hasInt = sc.hasNextInt();
            }
            int transactionId = sc.nextInt();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            

            PublicKey bankPublicKey = null;
            try {
                bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
                bankPublicKey = null;
            }
            do {
                bankResponse = api.receiveAmount(privateKey, myPort, bankPorts.get(0), bankAddress, bankNames.get(0), bankPublicKey, username, requestID, transactionId);
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
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_REQUEST_RETRIES);
            numberOfTries = 0;
            

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
            while(!isRegularInput(owner, false)) {
                System.out.println("Please enter a valid owner username.");
                owner = sc.nextLine();
            }

            int numberOfTries = 0;
            

            PublicKey bankPublicKey = null;
            try {
                bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
            }
            do {
                bankResponse = api.checkAccount(privateKey, myPort, bankPorts.get(0), bankAddress, bankNames.get(0), bankPublicKey, username, requestID, owner);
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
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_REQUEST_RETRIES);
            numberOfTries = 0;
            

        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }

        return requestID + 2;
    }

    private static int handleSendAmount(int myPort, InetAddress bankAddress, int requestID,
                                        Scanner sc, PrivateKey privateKey, String username) {

        String bankResponse;
        try {

            System.out.println("Please input username of receiver account (to fetch public key).");
            String usernameDest = sc.nextLine();
            while(!isRegularInput(usernameDest, false)) {
                System.out.println("Please enter a valid username.");
                usernameDest = sc.nextLine();
            }

            System.out.println("How much do you want to transfer?");
            boolean hasFloat = sc.hasNextFloat();
            while(!hasFloat) {
                System.out.println("Please input a valid amount.");
                hasFloat = sc.hasNextFloat();
            }
            float amount = sc.nextFloat();
            sc.nextLine(); //flush

            int numberOfTries = 0;
            

            PublicKey bankPublicKey = null;
            try {
                bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
            }
            do {
                bankResponse = api.sendAmount(privateKey, myPort, bankPorts.get(0), bankAddress, bankNames.get(0), bankPublicKey, requestID, username, amount, usernameDest);
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
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_REQUEST_RETRIES);
            numberOfTries = 0;
            
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
        while(!isRegularInput(username, false)) {
            System.out.println("Please enter a valid username.");
            username = sc.nextLine();
        }

        privateKeyPath = "keys/" + username + "_private_key.der";

        System.out.println("Please input alias for the keyStore entry.");
        String alias = sc.nextLine();
        while(!isRegularInput(alias, false)) {
            System.out.println("Please enter a valid alias.");
            alias = sc.nextLine();
        }

        System.out.println("Please input password for the keyStore.");
        String passwordString = sc.nextLine();
        while(!isRegularInput(passwordString, true)) {
            System.out.println("Please enter a valid password.");
            passwordString = sc.nextLine();
        }

        try {
            privateKey = readPrivate(privateKeyPath);
            int numberOfTries = 0;
            

            PublicKey bankPublicKey = null;
            try {
                bankPublicKey = readPublic("keys/" + bankNames.get(0) + "_public_key.der");
            } catch (GeneralSecurityException | IOException e) {
                logger.error("Error: ", e);
            }
            do {
                bankResponse = api.openAccount(privateKey, myPort, bankPorts.get(0), bankAddress, bankPublicKey, username, -1, bankNames.get(0));
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
            } while ((bankResponse.equals(ActionLabel.FAIL.getLabel())) && numberOfTries < MAX_REQUEST_RETRIES);
            numberOfTries = 0;
            
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Error: ", e);
        }
        privateKey = null;
    }

    private static boolean isRegularInput(String input, boolean pass) {
        Matcher m;
        if(!pass) {
            Pattern p1 = Pattern.compile(INPUT_CHARACTER_VALIDATION);
            m = p1.matcher(input);
            if(!m.matches()) {
                return false;
            }
        }
        Pattern p2 = Pattern.compile(INPUT_LENGTH_VALIDATION);
        m = p2.matcher(input);
        return m.matches();
    }

    private static void readConfig() {
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

    private static boolean solveRandomPuzzle(Scanner sc) {
        Random generator = new Random();
        Object[] keys = puzzles.keySet().toArray();
        String puzzle = (String) keys[generator.nextInt(keys.length)];
        System.out.println(puzzle);
        String answer = sc.nextLine();
        if(answer.equals(puzzles.get(puzzle))) {
            return true;
        } else {
            System.out.println("Wrong answer. Please try again.");
            return false;
        }
    }
}