package RESTService;

import SignatureService.PdfSignature;
import aux.Tuple;
import aux.VisualSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import org.apache.pdfbox.io.IOUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MimeType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
public class SigningController {

    ScheduledExecutorService sessionHandler = Executors.newSingleThreadScheduledExecutor();
    private final Map<String,List<Tuple<DSSDocument,PAdESSignatureParameters>>> sessions = new ConcurrentHashMap<>();
    private final PdfSignature service = new PdfSignature();

    /* Requests the signature for the files in an array and generates the session for them */
    /* Will throw IllegalStateException in case of empty array */
    private ResponseEntity<?> requestSign(Params params, MultipartFile[] files) throws IOException, IllegalStateException, CertificateException, NoSuchAlgorithmException {
        List<DSSDocument> documents = new ArrayList<>();

        for (MultipartFile file : files) {
            DSSDocument document = new InMemoryDocument(file.getBytes());
            document.setName(file.getOriginalFilename());
            documents.add(document);
        }

        if(params.getX() == null && params.getY() == null)
            return ResponseEntity.badRequest().build();

        VisualSignature visualSignature = new VisualSignature(params.getX(), params.getY());
        if(params.getPage() != null)
            visualSignature.setPage(params.getPage());

        Tuple<String, List<Tuple<DSSDocument,PAdESSignatureParameters>>> r;
        switch (documents.size()) {
            case 0 -> throw new IllegalStateException();
            case 1 -> {
                Tuple<String, PAdESSignatureParameters> tmp = service.makeSingleSigReq(documents.get(0), params.getUserid(), params.getPin(), visualSignature);
                r = new Tuple<>(tmp.x, Collections.singletonList(new Tuple<>(documents.get(0), tmp.y)));
            }
            default -> r = service.makeMultipleSigReq(documents, params.getUserid(), params.getPin(), visualSignature);
        }

        final String token = r.x;
        sessionHandler.schedule(() -> {
            System.out.println("Removing " + token);
            sessions.remove(token);
        }, 10, TimeUnit.MINUTES);
        sessions.put(r.x, r.y);

        return new ResponseEntity<>(new SigningRequestResponse(r.x), HttpStatus.OK);

    }

    @PostMapping("/requestsign")
    public ResponseEntity<?> RequestSign (
            @RequestPart("params") Params params,
            @RequestPart("file") MultipartFile[] files
    ) throws Exception {
        return requestSign(params, files);
    }


    /* Signs the documents in a session */
    public void fetchSign (SignSingleRequest req, HttpServletResponse response) throws IOException {
        try {
            List<Tuple<DSSDocument,PAdESSignatureParameters>> store = sessions.get(req.getOperationID());

            List<DSSDocument> signed = switch (store.size()) {
                case 0 -> throw new IllegalStateException();
                case 1 -> Collections.singletonList(service.sign(store.get(0).x, req.getOperationID(), req.getOtp(), store.get(0).y));
                default -> service.sign_Multiple(store, req.getOperationID(), req.getOtp());
            };

            ZipOutputStream zipOutputStream = new ZipOutputStream(response.getOutputStream());

            for (DSSDocument document : signed) {
                zipOutputStream.putNextEntry(new ZipEntry(document.getName()));
                IOUtils.copy(document.openStream(), zipOutputStream);
                zipOutputStream.closeEntry();
            }
            zipOutputStream.close();

        } finally {
            sessions.remove(req.getOperationID());
        }
    }

    @PostMapping("/fetchsign")
    public void SignMultipleFiles (
            @RequestBody SignSingleRequest req,
            HttpServletResponse response
    ) throws Exception {
        fetchSign(req, response);
    }

}
