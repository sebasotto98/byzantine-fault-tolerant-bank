package pt.tecnico;


public class BankHelper implements Runnable {

    @Override
    public void run() {
        String[] bankArgs = new String[1];
        bankArgs[0] = "9997";
        Bank.main(bankArgs);
    }


}
