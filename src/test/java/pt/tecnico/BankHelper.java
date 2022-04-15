package pt.tecnico;


public class BankHelper implements Runnable {

    @Override
    public void run() {
        String[] bankArgs = new String[2];
        bankArgs[0] = "9997";
        bankArgs[1] = "bank";
        Bank.main(bankArgs);
    }

}
