

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.AuthenticatedTimeStampTokenProvider;
import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.providers.impl.TSAHttpAuthenticationData;
import xades4j.utils.DOMHelper;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.providers.impl.*;

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 *
 * @author Joan Josep Escandell
 */
public class JoanEscandell {

    private static final String CERT_FOLDER = "E:/test/Certs/";
    private static final String CERT        = "rndCodesigning.p12";
    private static final String KEY_STORE   = "rndCodesigning.p12";
    private static final String PASS        = "P@ssw0rd"; //the same in cert and keystorage

    private static final String TSA_URL     = "http://time.teda.th";
    private static final String TSA_USER    = "rndStaff";
    private static final String TSA_PASS    = "rndP@ssw0rd";

    private static final String UNSIGNED    = "E:/Test/sign-verify/unsigned.xml";
    private static final String SIGNED      = "E:/Test/sign-verify/signed-bes.xml";
    private static final String SIGNEDT     = "C:/Test/sign-verify/signed-t-bes.xml";    
    private static final String VERIFY      = "C:/Test/sign-verify/verify-bes.txt";
    private static final String VERIFYT     = "C:/Test/sign-verify/verify-t-bes.txt";
    private static final String DOCUMENT    = "E:/Test/sign-verify/ETDA-invoice.xml";
//    private static final String DOCUMENT    = "E:/Test/sign-verify/data.xml";
    private static final String DOCSIGNED   = "C:/Test/sign-verify/signed.bes.xml";

    public static void main(String[] args) throws Exception {
        System.out.println("______________________");
        System.out.println("\tSign");
        System.out.println("______________________");
        signBes();
        
        System.out.println("______________________");
        System.out.println("\tVerify");
        System.out.println("______________________");
        //verifyBes();

    }

    private static void signBes() throws Exception {
        Document doc = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(new File(DOCUMENT));
        Element elem = doc.getDocumentElement();
        //DOMHelper.useIdAsXmlId(elem);
        //DOMHelper.setIdAsXmlId(elem, "20");
        

        KeyingDataProvider kdp = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                CERT_FOLDER + CERT,
                new FirstCertificateSelector(),
                new DirectPasswordProvider(PASS),
                new DirectPasswordProvider(PASS),
                true);
        DataObjectDesc obj = new DataObjectReference("#" + elem.getAttribute("Id"))
                .withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj);

        XadesSigner signer = new XadesBesSigningProfile(kdp).newSigner();
        signer.sign(dataObjs, elem);

        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer transformer = tFactory.newTransformer();
        DOMSource source = new DOMSource(doc);        
        StreamResult result = new StreamResult(new File(SIGNED));
        transformer.transform(source, result);
    }

    private static void signTBes() throws Exception {
        Document doc = DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(new File(UNSIGNED));
        Element elem = doc.getDocumentElement();
        //DOMHelper.useIdAsXmlId(elem);

        KeyingDataProvider kdp = new FileSystemKeyStoreKeyingDataProvider(
                "pkcs12",
                CERT_FOLDER + CERT,
                new FirstCertificateSelector(),
                new DirectPasswordProvider(PASS),
                new DirectPasswordProvider(PASS),
                true);
        DataObjectDesc obj = new DataObjectReference("#" + elem.getAttribute("Id"))
                .withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj);

        XadesSigner signer = new XadesTSigningProfile(kdp)
                .withTimeStampTokenProvider(
                        new AuthenticatedTimeStampTokenProvider(
                                new DefaultMessageDigestProvider(), 
                                new TSAHttpAuthenticationData(TSA_URL, TSA_USER, TSA_PASS)))
                .newSigner();
        signer.sign(dataObjs, elem);

        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer transformer = tFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(SIGNEDT));
        transformer.transform(source, result);
    }

    private static void verifyBes() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new FileReader(SIGNED)));
        DOMHelper.useIdAsXmlId(doc.getDocumentElement());

        NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

        FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(CERT_FOLDER);
        KeyStore ks;
        try (FileInputStream fis = new FileInputStream(CERT_FOLDER + KEY_STORE)) {
            ks = KeyStore.getInstance("jks");
            ks.load(fis, PASS.toCharArray());
        }

        CertificateValidationProvider provider = new PKIXCertificateValidationProvider(
                ks, false, certStore.getStore());
        XadesVerificationProfile profile = new XadesVerificationProfile(provider);
        Element sigElem = (Element) nl.item(0);
        XAdESVerificationResult r = profile.newVerifier().verify(sigElem, null);

        System.out.println("Signature form: " + r.getSignatureForm());
        System.out.println("Algorithm URI: " + r.getSignatureAlgorithmUri());
        System.out.println("Signed objects: " + r.getSignedDataObjects().size());
        System.out.println("Qualifying properties: " + r.getQualifyingProperties().all().size());
        
        for (QualifyingProperty qp : r.getQualifyingProperties().all()) {            
            if ("SigningCertificate".equals(qp.getName())) {
                Collection<X509Certificate> certs = ((SigningCertificateProperty)qp).getsigningCertificateChain();
                certs.forEach((cert) -> {
                    System.out.println("Issuer DN: " + cert.getIssuerDN());
                });
            }
            else if ("SigningTime".equals(qp.getName())) {
                System.out.println("Time: " + ((SigningTimeProperty)qp).getSigningTime().getTime().toString());
            } else if ("SignatureTimeStamp".equals(qp.getName())) {
                System.out.println("Time stamp: " + ((SignatureTimeStampProperty)qp).getTime().toString());
            }else { 
                System.out.println("QP: " + qp.getName());
            }
        }
    }
}
