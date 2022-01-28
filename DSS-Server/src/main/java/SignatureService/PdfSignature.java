package SignatureService;

import RESTService.Params;
import SignatureService.CMDSoap;
import aux.Tuple;
import aux.VisualSignature;
import com.itextpdf.text.pdf.PdfReader;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureAlgorithm.RSA_SHA256;

public class PdfSignature {

    private PAdESService service;
    private CMDSoap cmdSoap;

    public PdfSignature(){
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        this.service = new PAdESService(certificateVerifier);
        this.cmdSoap = new CMDSoap();
    }

    private PAdESSignatureParameters drawSigImage(String name, VisualSignature visualSig, PAdESSignatureParameters parameters) {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();


        DSSFont font = new PdfBoxNativeFont(PDType1Font.COURIER);
        font.setSize(10);
        textParameters.setFont(font);

        //System.out.println(name);
        textParameters.setText("Digitally Signed by:\n" + name);
        textParameters.setTextColor(Color.BLACK);


        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();


        fieldParameters.setOriginX(visualSig.getX());
        fieldParameters.setOriginY(visualSig.getY());
        fieldParameters.setWidth(200);
        fieldParameters.setHeight(50);
        fieldParameters.setPage(visualSig.getPage());

        imageParameters.setTextParameters(textParameters);
        imageParameters.setFieldParameters(fieldParameters);
        parameters.setImageParameters(imageParameters);

        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
        return parameters;

    }


    // Método que faz parse aos certificados provenientes do pedido 'getCertificates" do servidor Soap CMD
    // e retorna os repetivos certificados encapsulados num 'CertificateToken'
    private Tuple<CertificateToken,List<CertificateToken>> parseCertificates(String certificates) throws CertificateException {

        String[] tmp = certificates.split("-----END CERTIFICATE-----\n");
        String signing_certificate_string = tmp[0]+"-----END CERTIFICATE-----";
        String ca_string = tmp[2];
        String root_string = tmp[1].split("\n",2)[1]+"-----END CERTIFICATE-----";

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(signing_certificate_string.getBytes(StandardCharsets.UTF_8)));
        X509Certificate r = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(root_string.getBytes(StandardCharsets.UTF_8)));
        X509Certificate c = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(ca_string.getBytes(StandardCharsets.UTF_8)));


        CertificateToken user = new CertificateToken(cert);
        CertificateToken root = new CertificateToken(r);
        CertificateToken ca = new CertificateToken(c);

        List<CertificateToken> certificateChain = new ArrayList<>();
        certificateChain.add(root);
        certificateChain.add(ca);

        return new Tuple<>(user,certificateChain);
    }

    // Método que retorna o nome do assinante
    private String getSubjectNameFromCertificate(CertificateToken user){
        return user.getSubject().getPrettyPrintRFC2253().split("commonName=")[1].split(",")[0];
    }

    // Método que cria os parâmetros corretos para uma assinatura do tipo BASELINE_B
    private PAdESSignatureParameters get_BASELINE_B_Parameters(CertificateToken user, List<CertificateToken> certificateChain){
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(user);
        parameters.setCertificateChain(certificateChain);
        return parameters;
    }

    // Método que faz um pedido de assinatura ao servidor CMD
    // Retorna o id do pedido dado pelo Servidor CMD e os parâmetros utilizados
    public Tuple<String,PAdESSignatureParameters> makeSingleSigReq(DSSDocument document,String userId, String pin, VisualSignature visualSig) throws CertificateException, NoSuchAlgorithmException, IOException {
        // Pedido dos certificados ao Servidor CMD Soap e posterior parse dos mesmos
        Tuple<CertificateToken,List<CertificateToken>> certificates = this.parseCertificates(cmdSoap.getCertificates(userId));
        CertificateToken user = certificates.x;
        List<CertificateToken> certificateChain = certificates.y;


        // Criação dos parametros corretos para o tipo de assinatura
        PAdESSignatureParameters parameters;

        if(visualSig != null) {
            // Adicionar Assinatura Visual
            //System.out.println("Making a visual signature in page: " + visualSig.getPage() + " x: " + visualSig.getX() + " y: " + visualSig.getY());
            String name = this.getSubjectNameFromCertificate(user);
            if(visualSig.getPage() == -1){
                PdfReader reader = new PdfReader(document.openStream());
                visualSig.setPage(reader.getNumberOfPages());
                reader.close();
            }
            parameters = this.drawSigImage(name, visualSig, this.get_BASELINE_B_Parameters(user, certificateChain));
        }
        else
            parameters = this.get_BASELINE_B_Parameters(user,certificateChain);

        // Dados que serão assinados pelo Servidor CMD Soap ( a hash dos dados )
        ToBeSigned tbs = service.getDataToSign(document,parameters);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(tbs.getBytes());

        // Fazer um pedido para criar a assinatura do pdf utilizando o Servidor CMD Soap
        String resultCcMovelSign = cmdSoap.ccMovelSign(document.getName(), hash, userId, pin);

        // Retornar Tuplo com a string com o id do pedido (processId) e os parâmetros utilizados
        String processId = StringUtils.substringBefore(resultCcMovelSign, "ValidateOTP\n");
        return new Tuple<>(processId,parameters);
    }

    public Tuple<String,List<Tuple<DSSDocument,PAdESSignatureParameters>>> makeMultipleSigReq(List<DSSDocument> documents,String userId, String pin, VisualSignature visualSig) throws CertificateException, NoSuchAlgorithmException, IOException{
        // Pedido dos certificados ao Servidor CMD Soap e posterior parse dos mesmos
        Tuple<CertificateToken,List<CertificateToken>> certificates = this.parseCertificates(cmdSoap.getCertificates(userId));
        CertificateToken user = certificates.x;
        List<CertificateToken> certificateChain = certificates.y;

        List<byte[]> hashes = new ArrayList<>();
        List<String> docNames = new ArrayList<>();
        List<Tuple<DSSDocument,PAdESSignatureParameters>> doc_param = new ArrayList<>();
        for (DSSDocument document : documents) {
            // Criação dos parametros corretos para o tipo de assinatura
            PAdESSignatureParameters parameters;
            if(visualSig != null) { // Adicionar assinatura digital
                String name = this.getSubjectNameFromCertificate(user);
                PdfReader reader = new PdfReader(document.openStream());
                parameters = this.drawSigImage(name, visualSig, this.get_BASELINE_B_Parameters(user, certificateChain));
                parameters.getImageParameters().getFieldParameters().setPage(reader.getNumberOfPages());
                reader.close();
            } else {
                parameters = this.get_BASELINE_B_Parameters(user,certificateChain);
            }
            ToBeSigned tbs = service.getDataToSign(document, parameters);
            hashes.add(MessageDigest.getInstance("SHA-256").digest(tbs.getBytes()));
            docNames.add(document.getName());
            doc_param.add(new Tuple<>(document, parameters));
        }

        String resultCcMovelSign = cmdSoap.ccMovelMultSign(docNames,hashes,userId,pin);

        String processId = StringUtils.substringBefore(resultCcMovelSign, "ValidateOTP\n");
        return new Tuple<>(processId,doc_param);
    }


    public DSSDocument sign(DSSDocument document,String processId, String otpCode, PAdESSignatureParameters parameters){

        // Enviar o código OTP para receber a assinatura pedida anteriormente
        byte[] signature = cmdSoap.validateOtp(processId, otpCode);
        SignatureValue signatureValue = new SignatureValue(RSA_SHA256,signature);

        /*System.out.println("Confirming.... page: " + parameters.getImageParameters().getFieldParameters().getPage()
        + " x: " + parameters.getImageParameters().getFieldParameters().getOriginX()
        + " y: " + parameters.getImageParameters().getFieldParameters().getOriginY());*/

        // Colocar a assinatura no documento pdf
        return this.service.signDocument(document,parameters,signatureValue);
    }

    public  List<DSSDocument> sign_Multiple(List<Tuple<DSSDocument,PAdESSignatureParameters>> list, String processId, String otpCode) {


        List<byte[]> signatures = cmdSoap.validateOtpMult(processId,otpCode);

        List<DSSDocument> signed_documents = new ArrayList<>();

        int i = 0;
        for (Tuple<DSSDocument,PAdESSignatureParameters> t : list){
            byte[] sig = signatures.get(i);
            if (sig == null)
                continue;
            SignatureValue signatureValue = new SignatureValue(RSA_SHA256,sig);
            signed_documents.add(this.service.signDocument(t.x,t.y,signatureValue));
            i++;
        }

        return signed_documents;
    }


}

