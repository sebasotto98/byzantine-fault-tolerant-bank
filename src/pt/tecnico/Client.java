package pt.tecnico;

import java.security.PublicKey;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) {
        API api = new API();
        PublicKey key;
        Scanner sc = new Scanner(System.in);
        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Please enter your choice: ");
            ch = sc.nextInt();
            switch (ch) {
                case 1:
                    key = null;
                    api.openAccount(key);
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
