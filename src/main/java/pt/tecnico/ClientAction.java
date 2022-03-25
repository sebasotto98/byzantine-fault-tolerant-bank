package pt.tecnico;

public enum ClientAction {
    OPEN_ACCOUNT("OpenAccount"),
    SEND_AMOUNT("SendAmount"),
    CHECK_ACCOUNT("CheckAccount"),
    RECEIVE_AMOUNT("ReceiveAmount"),
    AUDIT_ACCOUNT("AuditAccount");

    private final String label;

    ClientAction(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
