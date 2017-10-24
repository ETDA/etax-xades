import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import util.CertHelper;
import xades4j.algorithms.XPath2FilterTransform.XPath2Filter;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CommitmentTypeProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.IndividualDataObjsTimeStampProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;

public class MbkSabri {
	private static final String FOLDERPATH = "E:/test/Certs/";
	private static final String PKCS11_LIB_PATH = FOLDERPATH + "eTOKCSP.dll";
	private static final String PROVIDER_NAME = "CSP";
	private static final String KEYSTORE_TYPE = "PKCS11KeyStore";

	public static void main(String[] args) {
		try {
			CertHelper certHelper = new CertHelper();

			// >>> TEST N°1
			X509Certificate[] chain = certHelper.promptSelectCertDialog();
			X509Certificate cert = chain[0];
			//String keyStoreType = "Windows-MY";
			KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
			keyStore.load(null, null) ;
			String alias = certHelper.getCNfromX509(chain[0].getSubjectX500Principal());
			PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, null);		
			KeyingDataProvider kp = new DirectKeyingDataProvider((X509Certificate) cert, privateKey);

			// >>> TEST N°2
			// KeyingDataProvider kp = new
			// PKCS11KeyStoreKeyingDataProvider(PKCS11_LIB_PATH, PROVIDER_NAME,
			// // CERTIFICATE
			// // NAME
			// new FirstCertificateSelector(), new
			// DirectPasswordProvider("1161"), // PIN
			// // CODE
			// new DirectPasswordProvider("1161"), // PIN CODE
			// false);

			// XADES
			XadesSigningProfile p = new XadesBesSigningProfile(kp);
			XadesSigner signer = p.newSigner();

			javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			javax.xml.parsers.DocumentBuilder builder = null;
			builder = factory.newDocumentBuilder();

			// XML FILE TO BE SIGNED
			Document doc1 = builder.parse(new File(FOLDERPATH + "FileNotSigned.xml"));

			// NODE
			Node parentElement = doc1.getDocumentElement();
			Node nodeToSign = doc1.getDocumentElement().getFirstChild();
			Node nodeToAttachSignature = doc1.getDocumentElement();

			IndividualDataObjsTimeStampProperty dataObjsTimeStamp = new IndividualDataObjsTimeStampProperty();
			AllDataObjsCommitmentTypeProperty globalCommitment = AllDataObjsCommitmentTypeProperty.proofOfApproval();
			CommitmentTypeProperty commitment = CommitmentTypeProperty.proofOfCreation();

			// XPATH STRING
			String xpathHeader = "/InvoiceHeader";
			String xpathBody = "/InvoiceBody";

			// OBJECT
			DataObjectDesc obj1 = new DataObjectReference("");
			obj1.withTransform(XPath2Filter.intersect(xpathHeader).intersect(xpathBody));
			SignedDataObjects dataObjs = new SignedDataObjects(obj1);

			// SIGN
			signer.sign(dataObjs, nodeToAttachSignature);

			// TRANSFORMER
			Transformer transformer = TransformerFactory.newInstance().newTransformer();

			// XML SIGNED
			Result output = new StreamResult(new File(FOLDERPATH + "FileSigned.xml"));
			Source input = new DOMSource(doc1);
			transformer.transform(input, output);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

	}
}
