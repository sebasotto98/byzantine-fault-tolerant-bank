package pt.tecnico;

import java.security.PublicKey;
import java.io.IOException;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Scanner;

public class Client {

    // PublicKey accountPublickey, PrivateKey accountPrivatekey, int clientPort, int clientId,
    //int serverPort, InetAddress serverAddress, PublicKey bankPublic
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        API api = new API();
        PublicKey publicKey;
        PrivateKey privateKey = null;
        int port = 0;
        int id = 0;
        int bankPort = 0;
        InetAddress bankAddress = null;
        PublicKey bankPublic = null;
        Scanner sc = new Scanner(System.in);
        int ch = 0;
        PublicKey key; // to remove when implemented
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            switch (ch) {
                case 1:
                    publicKey = null;
                    api.openAccount(publicKey, privateKey, port, id, bankPort, bankAddress, bankPublic);
                    break;
                case 2:
                    PublicKey sourceKey = null;
                    PublicKey destKey = null;
                    float amount = 0;
                    api.sendAmount(sourceKey, destKey, amount);
                    break;
                case 3:
                    key = null;
                    api.checkAccount(key);
                    break;
                case 4:
                    key = null;
                    api.receiveAmount(key);
                    break;
                case 5:
                    key = null;
                    api.audit(key);
                    break;
                case 6:
                    break;
                default:
                    System.out.println("Please enter valid option.");
            }
        }
    }
}
