package SignatureService;

import com.google.common.primitives.Bytes;
import wsdlservice.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class CMDSoap {

    private final CCMovelDigitalSignature service;
    private final CCMovelSignature conn;
    private final String applicationId;

    public CMDSoap(){
        this.service = new CCMovelDigitalSignature();
        this.conn = service.getBasicHttpBindingCCMovelSignature();
        this.applicationId  = "";
    }

    public byte[] getApplicationId() {
        return applicationId.getBytes();
    }

    public String getCertificates(String userId) {
        return conn.getCertificate(this.getApplicationId(),userId);
    }


    public String ccMovelSign(String docName, byte[] hash, String userId, String userPin) {

        SignRequest request = new SignRequest();
        request.setApplicationId(this.getApplicationId());

        ObjectFactory objectFactory = new ObjectFactory();

        request.setDocName(objectFactory.createSignRequestDocName(docName));

        byte[] prefix = Base64.getDecoder().decode("MDEwDQYJYIZIAWUDBAIBBQAEIA==");

        request.setHash(Bytes.concat(prefix,hash));

        request.setUserId(userId);
        request.setPin(userPin);

        SignStatus status = conn.ccMovelSign(request);

        //System.out.println(status.getMessage());

        return status.getProcessId();
    }

    public String ccMovelMultSign(List<String> docNames, List<byte[]> hashes, String userId, String UserPin){

        MultipleSignRequest request = new MultipleSignRequest();
        request.setApplicationId(this.getApplicationId());
        request.setUserId(userId);
        request.setPin(UserPin);

        byte[] prefix = Base64.getDecoder().decode("MDEwDQYJYIZIAWUDBAIBBQAEIA==");

        ArrayOfHashStructure documents = new ArrayOfHashStructure();
        int id = 0;
        for(byte[] hash : hashes){
            HashStructure s = new HashStructure();
            s.setHash(Bytes.concat(prefix,hash));
            s.setName(docNames.get(id));
            s.setId(Integer.toString(id));
            id++;

            documents.getHashStructure().add(s);
            //System.out.println("id: " + s.getId() + " " + Arrays.toString(s.getHash()));
        }

        SignStatus status = conn.ccMovelMultipleSign(request,documents);

        //System.out.println(status.getMessage());

        return status.getProcessId();
    }

    public byte[] validateOtp(String processId, String otpCode) {

        SignResponse response = conn.validateOtp(otpCode, processId, this.getApplicationId());

        //System.out.println(response.getStatus().getMessage());

        return response.getSignature();
    }

    public List<byte[]> validateOtpMult(String processId, String otpCode) {

        SignResponse response = conn.validateOtp(otpCode, processId, this.getApplicationId());

        //System.out.println(response.getStatus().getMessage());

        List<byte[]> signatures = new ArrayList<>();

        for(HashStructure a : response.getArrayOfHashStructure().getHashStructure()){
            signatures.add(a.getHash());
            //System.out.println(a.getId() + ": " + Arrays.toString(a.getHash()));
        }

        return signatures;
    }
}
