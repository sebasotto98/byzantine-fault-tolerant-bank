package pt.tecnico;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class SharedBankVars {
    //share variables between threads
    private static final AtomicInteger transactionId = new AtomicInteger(0);

    private static final AtomicInteger bankRequestId = new AtomicInteger(0);

    //locks to access files
    private static final Object clientsFileLock = new Object();
    private static final Object requestIdFileLock = new Object();
    private static final Object signaturesFileLock = new Object();
    private static final Object transactionIdFileLock = new Object();
    private static final Object pendingTransactionsSignatureFileLock = new Object();
    private static final Object completedTransactionsSignatureFileLock = new Object();

    //each element is a lock for a client transaction file
    private static final Map<String, Object> clientsLock = new ConcurrentHashMap<>();

    public synchronized Object getClientLock(String client) {
        return clientsLock.computeIfAbsent(client, k -> new Object());
    }

    public Object getClientsFileLock() {
        return clientsFileLock;
    }

    public Object getRequestIdFileLock() {
        return requestIdFileLock;
    }

    public Object getSignaturesFileLock() {
        return signaturesFileLock;
    }

    public Object getTransactionIdFileLock() {
        return signaturesFileLock;
    }

    public Object getPendingTransactionsSignatureFileLock(){
        return pendingTransactionsSignatureFileLock;
    }

    public static Object getCompletedTransactionsSignatureFileLock() {
        return completedTransactionsSignatureFileLock;
    }

    //methods for the sharedVars
    public AtomicInteger getTransactionId() {
        return transactionId;
    }

    public synchronized void incrementTransactionId() {
        transactionId.incrementAndGet();
    }

    public AtomicInteger getBankRequestId() {
        return bankRequestId;
    }

    public synchronized void incrementBankRequestID() {
        bankRequestId.incrementAndGet();
    }

}