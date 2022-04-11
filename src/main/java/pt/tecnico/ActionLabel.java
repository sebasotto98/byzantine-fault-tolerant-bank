package pt.tecnico;

public enum ActionLabel {
    //request labels
    OPEN_ACCOUNT("OpenAccount"),
    SEND_AMOUNT("SendAmount"),
    CHECK_ACCOUNT("CheckAccount"),
    RECEIVE_AMOUNT("ReceiveAmount"),
    AUDIT_ACCOUNT("AuditAccount"),

    //TODO label
    TODO("TODO"),

    //response labels
    ACCOUNT_CREATED("AccountCreated"),
    DUPLICATE_USERNAME("DuplicateUsername"),
    PENDING_TRANSACTION("PendingTransaction"),
    INSUFFICIENT_AMOUNT("InsufficientAmount"),
    NEGATIVE_AMOUNT("NegativeAmount"),
    CLIENT_NOT_FOUND("ClientNotFound"),
    CLIENT_NOT_RECEIVER("ClientNotReceiver"),
    COMPLETED_TRANSACTION("CompletedTransaction"),

    //generic labels
    FAIL("Fail"),
    SUCCESS("Success"),

    //other labels
    UNKNOWN_FUNCTION("UNKNOWN_FUNCTION");

    private final String label;

    ActionLabel(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
