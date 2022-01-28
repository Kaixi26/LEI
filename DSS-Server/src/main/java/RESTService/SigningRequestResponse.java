package RESTService;

public class SigningRequestResponse {

    private final String operationID;

    public SigningRequestResponse(String operationID) {
        this.operationID = operationID;
    }

    public String getOperationID() {
        return operationID;
    }
}
