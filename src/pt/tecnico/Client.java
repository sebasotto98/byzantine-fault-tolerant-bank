package pt.tecnico;

import pt.tecnico.API;

import java.util.Scanner;

public class Client {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int ch = 0;
        while (ch!=6) {
            System.out.println("\n ***BFTB***");
            System.out.println("1. Open Account \n2. Send amount \n3. Check account \n4. Receive amount \n5. Audit account \n6. Exit ");
            System.out.println("Enter your choice: ");
            ch = sc.nextInt();
        }
    }
}
