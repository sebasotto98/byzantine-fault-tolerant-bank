package pt.tecnico;

public enum ActionLabel {
    //Request labels
    OPEN_ACCOUNT("OpenAccount"),
    SEND_AMOUNT("SendAmount"),
    CHECK_ACCOUNT("CheckAccount"),
    RECEIVE_AMOUNT("ReceiveAmount"),
    AUDIT_ACCOUNT("AuditAccount"),
    REQUEST_MY_ID("RequestMyId"),
    REQUEST_BANK_ID("RequestBankId"),
    SIGN("Sign"),
    WRITE_BACK("WriteBack"),

    //TODO label
    TODO("TODO"),

    //Response labels
    ACCOUNT_CREATED("AccountCreated"),
    DUPLICATE_USERNAME("DuplicateUsername"),
    PENDING_TRANSACTION("PendingTransaction"),
    INSUFFICIENT_AMOUNT("InsufficientAmount"),
    NEGATIVE_AMOUNT("NegativeAmount"),
    CLIENT_NOT_FOUND("ClientNotFound"),
    CLIENT_NOT_RECEIVER("ClientNotReceiver"),
    COMPLETED_TRANSACTION("CompletedTransaction"),

    //Generic labels
    FAIL("Fail"),
    SUCCESS("Success"),

    //Write Back labels
    AUDITING("Auditing"),
    CHECKING("Checking"),

    //Algorithm labels
    READ("Read"),
    WRITE("Write"),

    //Other labels
    UNKNOWN_FUNCTION("UNKNOWN_FUNCTION");

    private final String label;

    ActionLabel(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}