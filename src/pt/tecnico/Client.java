package pt.tecnico;

import java.io.FileInputStream;
import java.security.*;
import java.io.IOException;
import java.net.InetAddress;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

public class Client {

    public static KeyPair read(String publicKeyPath, String privateKeyPath) throws GeneralSecurityException, IOException {
        System.out.println("Reading public key from file " + publicKeyPath + " ...");
        FileInputStream pubFis = new FileInputStream(publicKeyPath);
        byte[] pubEncoded = new byte[pubFis.available()];
        pubFis.read(pubEncoded);
        pubFis.close();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);

        System.out.println("Reading private key from file " + privateKeyPath + " ...");
        FileInputStream privFis = new FileInputStream(privateKeyPath);
        byte[] privEncoded = new byte[privFis.available()];
        privFis.read(privEncoded);
        privFis.close();

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

        KeyPair keys = new KeyPair(pub, priv);
        return keys;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        API api = new API();

        int port = 9998;
        int id = 0;
        int bankPort = 9999;
        InetAddress bankAddress = InetAddress.getLocalHost();

        KeyPair keys = read("keys/pis_public_key.der","keys/pis_private_key.der");
        PublicKey publicKey = keys.getPublic();
        PrivateKey privateKey = keys.getPrivate();
        PublicKey bankPublicKey = null;

        Scanner sc = new Scanner(System.in);
        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            switch (ch) {
                case 1:
                    int accountOpened = api.openAccount(publicKey, privateKey, port, id, bankPort, bankAddress, bankPublicKey);
                    if(accountOpened == API.CORRECT) {
                        System.out.println("Account opened successfully!");
                    } else if(accountOpened == API.FAIL) {
                        System.out.println("Failed to open account.");
                    }
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
