package pt.tecnico;

import java.io.FileInputStream;
import java.security.*;
import java.io.IOException;
import java.net.InetAddress;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {

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

    public static PrivateKey readPrivate(String privateKeyPath) throws GeneralSecurityException, IOException {
        System.out.println("Reading private key from file " + privateKeyPath + " ...");
        FileInputStream privFis = new FileInputStream(privateKeyPath);
        byte[] privEncoded = new byte[privFis.available()];
        privFis.read(privEncoded);
        privFis.close();

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

        return priv;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        if (args.length < 2) {
            System.err.println("Argument(s) missing!");
            return;
        }
        final int port = Integer.parseInt(args[0]);
        int bankPort = Integer.parseInt(args[1]);
        InetAddress bankAddress = InetAddress.getLocalHost();

        int requestID = 0;
        API api = new API();
        PublicKey bankPublicKey = readPublic("keys/bank_public_key.der");
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String username = null;
        String publicKeyPath = null;
        String privateKeyPath = null;
        Scanner sc = new Scanner(System.in);

        String bankResponse;

        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            sc.nextLine();//flush
            switch (ch) {
                case 1:
                    System.out.println("Please input your username (to fetch public and private key).");
                    username = sc.nextLine();
                    publicKeyPath = "keys/"+username+"_public_key.der";
                    privateKeyPath = "keys/"+username+"_private_key.der";

                    publicKey = readPublic(publicKeyPath);
                    privateKey = readPrivate(privateKeyPath);
                    bankResponse = api.openAccount(publicKey, privateKey, port, bankPort, bankAddress, bankPublicKey, username, requestID);
                    requestID++;
                    if(bankResponse.equals(ActionLabel.SUCCESS.getLabel())) {
                        System.out.println("Account opened successfully!");
                    } else if(bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                        System.out.println("Failed to open account.");
                    }
                    publicKey = null;
                    privateKey = null;
                    break;
                case 2:
                    System.out.println("Please input your username (to fetch public and private key).");
                    username = sc.nextLine();
                    publicKeyPath = "keys/"+username+"_public_key.der";
                    privateKeyPath = "keys/"+username+"_private_key.der";
                    publicKey = readPublic(publicKeyPath);
                    privateKey = readPrivate(privateKeyPath);
                    
                    System.out.println("Please input username of receiver account (to fetch public key).");
                    String usernameDest = sc.nextLine();
                    //irrelevant???
                    publicKeyPath = "keys/" + usernameDest + "_public_key.der";
                    PublicKey destKey = readPublic(publicKeyPath);

                    System.out.println("How much do you want to transfer?");
                    float amount = sc.nextFloat();
                    sc.nextLine(); //flush
                    bankResponse = api.sendAmount(publicKey, privateKey, destKey, port, bankPort, bankAddress, bankPublicKey, requestID, username, amount, usernameDest);
                    requestID++;

                    if(bankResponse.equals(ActionLabel.PENDING_TRANSACTION.getLabel())) {
                        System.out.println("Transaction waiting for receiver approval!");
                    } else if(bankResponse.equals(ActionLabel.FAIL.getLabel())) {
                        System.out.println("Failed to send amount. An error occurred.");
                    } else if(bankResponse.equals(ActionLabel.INSUFFICIENT_AMOUNT.getLabel())) {
                        System.out.println("Insufficient available amount on sender account.");
                    } else if(bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())) {
                        System.out.println("Sender/Receiver account not found!");
                    }

                    publicKey = null;
                    privateKey = null;
                    break;
                case 3:
                    System.out.println("Please input your username (to fetch public and private key).");
                    username = sc.nextLine();
                    publicKeyPath = "keys/"+username+"_public_key.der";
                    privateKeyPath = "keys/"+username+"_private_key.der";
                    publicKey = readPublic(publicKeyPath);
                    privateKey = readPrivate(privateKeyPath);

                    System.out.println("Please input username of the account's owner (to fetch public key).");
                    String owner = sc.nextLine();

                    publicKeyPath = "keys/" + owner + "_public_key.der";
                    PublicKey ownerKey = readPublic(publicKeyPath);

                    bankResponse = api.checkAccount(publicKey, privateKey, port, bankPort, bankAddress, bankPublicKey, username, requestID, owner, ownerKey);
                    requestID++;

                    if(bankResponse.equals(ActionLabel.CLIENT_NOT_FOUND.getLabel())){
                        System.out.println("Owner's account not found!");
                    } else if(bankResponse.equals(ActionLabel.FAIL.getLabel())){
                        System.out.println("Error trying to read clients file or owner's pending transactions file.");
                    } else {

                        System.out.println("Account details: ");
                        String[] messages = bankResponse.split(";");
                        String[] accountDetails = messages[0].split(",");
                        System.out.println("Account's owner: " + accountDetails[0]);
                        System.out.println("Available amount: " + accountDetails[1]);
                        System.out.println("Book amount: " + accountDetails[2]);
                        System.out.println("Pending transactions associated with the account: ");
                        for(int i = 1; i < messages.length; i++){
                            String[] s = messages[i].split(",");

                            String str = "At " +
                                    s[0] +
                                    " user " +
                                    s[1] +
                                    " sent " +
                                    s[3] +
                                    " euros to user " +
                                    s[2] +
                                    ". Transaction waiting approval.";
                            System.out.println(str);
                        }
                    }

                    break;
                case 4:
                    api.receiveAmount(publicKey);
                    break;
                case 5:
                    api.audit(publicKey);
                    break;
                case 6:
                    break;
                default:
                    System.out.println("Please enter a valid option.");
            }
        }
    }
}
