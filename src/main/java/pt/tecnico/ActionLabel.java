package pt.tecnico;

public enum ActionLabel {
    //request labels
    OPEN_ACCOUNT("OpenAccount"),
    SEND_AMOUNT("SendAmount"),
    CHECK_ACCOUNT("CheckAccount"),
    RECEIVE_AMOUNT("ReceiveAmount"),
    AUDIT_ACCOUNT("AuditAccount"),

    //TODO
    TODO("TODO"),

    //response labels
    ACCOUNT_CREATED("AccountCreated"),
    PENDING_TRANSACTION("PendingTransaction"),

    //OTHERS
    UNKNOWN_FUNCTION("UNKNOWN_FUNCTION");

    private final String label;

    ActionLabel(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
