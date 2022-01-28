package RESTService;

public class SignSingleRequest {

    private final String operationID;
    private final String otp;

    public SignSingleRequest(String operationID, String otp) {
        this.operationID = operationID;
        this.otp = otp;
    }

    public String getOperationID() {
        return operationID;
    }

    public String getOtp() {
        return otp;
    }
}
