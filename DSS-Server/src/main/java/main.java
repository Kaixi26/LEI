import SignatureService.PdfSignature;
import aux.Tuple;
import aux.VisualSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class main {
    public static void main(String[] args) {
        // THIS IS A TEST CLASS, THE MAIN CLASS FOR THE SERVER RESIDES AT RESTService/RestServiceApplication
        PdfSignature pdf = new PdfSignature();
        try {

            DSSDocument document = new FileDocument("src/main/resources/TESTE_ASSINATURAS.pdf");
            //List<DSSDocument> documents = new ArrayList<>();

            //for(int i=1; i<=99 ; i++){
            //    DSSDocument document = new FileDocument("src/main/resources/pdfgen/" + Integer.toString(i) + ".pdf");
            //    documents.add(document);
            //}

            Scanner myScanner = new Scanner(System.in);

            System.out.println("Enter userId (+351NNNNNNNNN):");
            String userId = myScanner.nextLine();
            System.out.println("Enter PIN:");
            String pin = myScanner.nextLine();

            VisualSignature visualSig = new VisualSignature(250,250);

            Tuple<String, PAdESSignatureParameters> req = pdf.makeSingleSigReq(document,userId,pin,visualSig);

            //Tuple<String, List<Tuple<DSSDocument,PAdESSignatureParameters>>> req = pdf.makeMultipleSigReq(documents,userId,pin,visualSig);

            System.out.println("Enter the OTP received on your Device:");
            String otpCode = myScanner.nextLine();

            DSSDocument signed = pdf.sign(document, req.x, otpCode, req.y);
            //List<DSSDocument> signed_docs = pdf.sign_Multiple(req.y,req.x,otpCode);

            signed.save("src/main/resources/1_ASSINADO_DSS-2.pdf");
            //for( DSSDocument doc : signed_docs){
            //    doc.save("src/main/resources/pdfgen-signed/" + doc.getName());
            //}


        } catch (Exception e){
            System.out.println("Erro");
            e.printStackTrace();
        }

    }
}
