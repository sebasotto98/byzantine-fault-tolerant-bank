package pt.tecnico;

import java.util.concurrent.atomic.AtomicInteger;

public class VolatileBankInfo {
    //share variables between threads
    private static volatile AtomicInteger transactionId = new AtomicInteger(0);

    private static volatile AtomicInteger bankRequestId = new AtomicInteger(0);

    public AtomicInteger getTransactionId(){
        return transactionId;
    }

    public void incrementTransactionId(){
        transactionId.incrementAndGet();
    }

    public AtomicInteger getBankRequestId() {
        return bankRequestId;
    }

    public void incrementBankRequestID(){
        bankRequestId.incrementAndGet();
    }
}
