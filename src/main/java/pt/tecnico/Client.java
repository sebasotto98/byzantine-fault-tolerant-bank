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

        API api = new API();
        PublicKey bankPublicKey = readPublic("keys/bank_public_key.der");
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        Scanner sc = new Scanner(System.in);
        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            switch (ch) {
                case 1:
                    System.out.println("What's the username? (to fetch public and private key");
                    sc.nextLine();
                    String username = sc.nextLine();
                    String publicKeyPath = "keys/"+username+"_public_key.der";
                    String privateKeyPath = "keys/"+username+"_private_key.der";
                    publicKey = readPublic(publicKeyPath);
                    privateKey = readPrivate(privateKeyPath);
                    int accountOpened = api.openAccount(publicKey, privateKey, port, bankPort, bankAddress, bankPublicKey, username);
                    if(accountOpened == API.CORRECT) {
                        System.out.println("Account opened successfully!");
                    } else if(accountOpened == API.FAIL) {
                        System.out.println("Failed to open account.");
                    }
                    publicKey = null;
                    privateKey = null;
                    break;
                case 2:
                    PublicKey sourceKey = null;
                    PublicKey destKey = null;
                    float amount = 0;
                    api.sendAmount(sourceKey, destKey, amount);
                    break;
                case 3:
                    api.checkAccount(publicKey);
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
