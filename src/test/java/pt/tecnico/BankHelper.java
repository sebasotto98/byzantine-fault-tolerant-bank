package pt.tecnico;

public class BankHelper implements Runnable {

    private final String name;

    public BankHelper(String name) {
        this.name = name;
    }

    @Override
    public void run() {
        String[] bankArgs = new String[1];
        bankArgs[0] = name;
        Bank.main(bankArgs);
    }

}
