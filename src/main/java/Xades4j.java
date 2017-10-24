
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import util.CertHelper;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.impl.AuthenticatedTimeStampTokenProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.providers.impl.TSAHttpAuthenticationData;
import xades4j.utils.DOMHelper;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.UnexpectedJCAException;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;

public class Xades4j {

	private static final String FOLDERPATH = "src/main/resources/";
	private static final String KEYSTOREPATH = FOLDERPATH + "rndCodesigning.p12";
	private static final String KEYSTOREPATH_ROOT = FOLDERPATH + "rndCodesigning.p12";
	private static final String PASS = "P@ssw0rd";

	private static final String SIGN_FOLDERPATH = "target/";
	private static final String UNSIGNED = FOLDERPATH + "data.xml";
	private static final String CANONICAL = SIGN_FOLDERPATH + "canonical.xml";
	private static final String SIGNED = SIGN_FOLDERPATH + "signed-bes.xml";

	private static final String TSA_URL = "http://time.teda.th";
	private static final String TSA_USER = "rndStaff";
	private static final String TSA_PASS = "rndP@ssw0rd";

	private static final String PKCS11_LIB_PATH = FOLDERPATH + "eTOKCSP.dll";
	private static final String PROVIDER_NAME = "CSP";
	//private static final String CONFIG_FILE_PATH = FOLDERPATH + "config.cfg";
	private static final String KEYSTORE_TYPE = "Windows-MY";
	
	private static CertHelper certHelper;

	public Xades4j() {
		ResourceResolver.register("com.uk.nmi.sw.datavaulttesting.vaulttestingutils.xades.XPointerResourceResolver");
	}

	public static void main(String[] args) throws Exception {
		certHelper = new CertHelper();
		// System.out.println(System.getenv("SystemRoot"));
		System.out.println("==============\tSet canonicalXML\t==============");
		Path path = Paths.get(UNSIGNED);
		byte[] canoXML = canonicalXML(Files.readAllBytes(path));
		Path path2 = Paths.get(CANONICAL);
		Files.write(path2, canoXML);
		System.out.println("==============\tSet KeyStore\t==============");
		// XadesSigner signer = getSigner(PASS, KEYSTOREPATH);
		XadesSigner signer = getSigner();
		System.out.println("==============\tSign\t==============");
		signWithoutIDEnveloped(CANONICAL, SIGNED, signer);
		//System.out.println("==============\tVerify\t==============");
		//verifyBes(SIGNED);
		verifyBesWindowStore(SIGNED);
		System.out.println("==============\tFinish\t==============");
	}

	public static byte[] canonicalXML(byte[] xmlData) {
		// org.apache.xml.security.Init
		Init.init();
		Canonicalizer c14n = null;
		try {
			// Get Canonicalizer's instance, "ALGO_ID_C14N_OMIT_COMMENTS" =
			// ignore comment in xml
			c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		} catch (InvalidCanonicalizerException e) {
			e.printStackTrace();
		}

		byte[] out = null;
		try {
			// Do canonicalize
			out = c14n.canonicalize(xmlData);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return out;
	}

	public static XadesSigner getSigner(String password, String pfxPath) throws Exception {// SigningException
																							// {
		try {
			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {

				@Override
				public String getDigestAlgorithmForDataObjsReferences() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public String getDigestAlgorithmForReferenceProperties() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
					return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
				}
			};

			// KeyingDataProvider keyingProvider =
			// getKeyingDataProvider(pfxPath, password);
			KeyingDataProvider keyingProvider = getKeyingDataProvider();
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withTimeStampTokenProvider(new AuthenticatedTimeStampTokenProvider(new DefaultMessageDigestProvider(),
					new TSAHttpAuthenticationData(TSA_URL, TSA_USER, TSA_PASS)));
			p.withAlgorithmsProviderEx(ap);

			return p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
		/*
		 * } catch (KeyStoreException ex) { throw new SigningException(
		 * "Keystore Problem : " + ex); } catch (SigningCertChainException ex) {
		 * throw new SigningException("Signer Cert Chain Problem", ex); } catch
		 * (UnexpectedJCAException ex) { throw new SigningException(
		 * "JCA Problem getting Signer", ex); } catch
		 * (XadesProfileResolutionException ex) { throw new SigningException(
		 * "XadesProfileResolutionException problem geting Signer", ex); }
		 */
	}

	private static KeyingDataProvider getKeyingDataProvider(String pfxPath, String password)
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException {

		KeyingDataProvider keyingProvider = new FileSystemKeyStoreKeyingDataProvider("pkcs12", pfxPath,
				new SigningCertSelector() {

					@Override
					public X509Certificate selectCertificate(List<X509Certificate> list) {
						return list.get(0);
					}
				}, new DirectPasswordProvider(password), new DirectPasswordProvider(password), true);
		if (keyingProvider.getSigningCertificateChain().isEmpty()) {
			throw new IllegalArgumentException("Cannot initialize keystore with path " + pfxPath);
		}
		return keyingProvider;
	}

	/**
	 * Generate the signature and output a single signed file using the
	 * enveloped structure This means that the signature is within the signed
	 * XML This method signs the root node, not an ID
	 * 
	 * @param outputPath
	 * @param signer
	 * @param valid
	 * @throws TransformerFactoryConfigurationError
	 * @throws XAdES4jException
	 * @throws TransformerConfigurationException
	 * @throws TransformerException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	private static void signWithoutIDEnveloped(String inputPath, String outputPath, XadesSigner signer)
			throws TransformerFactoryConfigurationError, XAdES4jException, TransformerConfigurationException,
			TransformerException, IOException, FileNotFoundException {

		// X509Certificate[] chain = promptSelectCertDialog();
		// Copy source doc into target document
		// Document sourceDoc = getDocument(".\\080.xml");
		Document sourceDoc = getDocument(inputPath);
		sourceDoc.setDocumentURI(null);

		writeXMLToFile(sourceDoc, outputPath);

		sourceDoc = getDocument(outputPath);

		Element signatureParent = (Element) sourceDoc.getDocumentElement();
		Element elementToSign = sourceDoc.getDocumentElement();
		String refUri;
		if (elementToSign.hasAttribute("Id")) {
			refUri = '#' + elementToSign.getAttribute("Id");
		} else {
			if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
				throw new IllegalArgumentException("Element without Id must be the document root");
			}
			refUri = "";
		}

		DataObjectDesc dataObjRef = new DataObjectReference(refUri).withTransform(new EnvelopedSignatureTransform());

		XadesSignatureResult result = signer.sign(new SignedDataObjects(dataObjRef), signatureParent);
		writeXMLToFile(sourceDoc, outputPath);
	}

	/**
	 * Write an XML document to file
	 * 
	 * @param doc
	 *            The document
	 * @param outputPath
	 *            The path to write the XML file to
	 * @throws IOException
	 * @throws TransformerConfigurationException
	 * @throws TransformerFactoryConfigurationError
	 * @throws TransformerException
	 * @throws FileNotFoundException
	 */
	private static void writeXMLToFile(Document doc, String outputPath)
			throws IOException, TransformerConfigurationException, TransformerFactoryConfigurationError,
			TransformerException, FileNotFoundException {
		// Write the output to a file
		Source source = new DOMSource(doc);

		// Prepare the output file
		File outFile = new File(outputPath);
		outFile.getParentFile().mkdirs();
		outFile.createNewFile();
		FileOutputStream fos = new FileOutputStream(outFile);

		StreamResult result = new StreamResult(fos);

		// Write the DOM document to the file
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.transform(source, result);

		fos.close();
	}

	/**
	 * Load a Document from an XML file
	 * 
	 * @param path
	 *            The path to the file
	 * @return The document extracted from the file
	 */
	private static Document getDocument(String path) {
		try {
			// Load the XML to append the signature to.
			File fXmlFile = new File(path);
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);
			doc.getDocumentElement().normalize();
			return doc;
		} catch (SAXException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		} catch (ParserConfigurationException ex) {
			return null;
		}
	}

	private static void verifyBes(String filePath) throws Exception {

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new FileReader(filePath)));
		DOMHelper.useIdAsXmlId(doc.getDocumentElement());

		NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

		FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(FOLDERPATH);
		KeyStore ks;
		try (FileInputStream fis = new FileInputStream(KEYSTOREPATH)) {
			ks = KeyStore.getInstance("jks");
			ks.load(fis, PASS.toCharArray());
		}

		CertificateValidationProvider provider = new PKIXCertificateValidationProvider(ks, false, certStore.getStore());
		XadesVerificationProfile profile = new XadesVerificationProfile(provider);
		Element sigElem = (Element) nl.item(0);
		XAdESVerificationResult r = profile.newVerifier().verify(sigElem, null);

		System.out.println("Signature form: " + r.getSignatureForm());
		System.out.println("Algorithm URI: " + r.getSignatureAlgorithmUri());
		System.out.println("Signed objects: " + r.getSignedDataObjects().size());
		System.out.println("Qualifying properties: " + r.getQualifyingProperties().all().size());

		for (QualifyingProperty qp : r.getQualifyingProperties().all()) {
			if ("SigningCertificate".equals(qp.getName())) {
				Collection<X509Certificate> certs = ((SigningCertificateProperty) qp).getsigningCertificateChain();
				certs.forEach((cert) -> {
					System.out.println("Issuer DN: " + cert.getIssuerDN());
				});
			} else if ("SigningTime".equals(qp.getName())) {
				System.out.println("Time: " + ((SigningTimeProperty) qp).getSigningTime().getTime().toString());
			} else if ("SignatureTimeStamp".equals(qp.getName())) {
				System.out.println("Time stamp: " + ((SignatureTimeStampProperty) qp).getTime().toString());
			} else {
				System.out.println("QP: " + qp.getName());
			}
		}
	}

	public static XadesSigner getSigner() throws Exception {// SigningException
		// {
		try {
			AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {

				@Override
				public String getDigestAlgorithmForDataObjsReferences() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public String getDigestAlgorithmForReferenceProperties() {
					return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
				}

				@Override
				public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
					return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
				}
			};
			//AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx();

			KeyingDataProvider keyingProvider = getKeyingDataProvider();
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withTimeStampTokenProvider(new AuthenticatedTimeStampTokenProvider(new DefaultMessageDigestProvider(),
					new TSAHttpAuthenticationData(TSA_URL, TSA_USER, TSA_PASS)));
			p.withAlgorithmsProviderEx(ap);

			return p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
		/*
		 * } catch (KeyStoreException ex) { throw new SigningException(
		 * "Keystore Problem : " + ex); } catch (SigningCertChainException ex) {
		 * throw new SigningException("Signer Cert Chain Problem", ex); } catch
		 * (UnexpectedJCAException ex) { throw new SigningException(
		 * "JCA Problem getting Signer", ex); } catch
		 * (XadesProfileResolutionException ex) { throw new SigningException(
		 * "XadesProfileResolutionException problem geting Signer", ex); }
		 */
	}

	private static KeyingDataProvider getKeyingDataProvider()
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {

		// Provider p = new sun.security.pkcs11.SunPKCS11(CONFIG_FILE_PATH);
		// Security.addProvider(p);
		X509Certificate[] chain = certHelper.promptSelectCertDialog();
		X509Certificate cert = chain[0];
		//String keyStoreType = "Windows-MY";
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
		keyStore.load(null, null) ;
		String alias = certHelper.getCNfromX509(chain[0].getSubjectX500Principal());
		PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, null);			
		KeyingDataProvider keyingProvider = new DirectKeyingDataProvider((X509Certificate) cert, privateKey);
//		KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(PKCS11_LIB_PATH, PROVIDER_NAME,
//				new FirstCertificateSelector(), new DirectPasswordProvider("1161"), null, false);
		return keyingProvider;
	}

	
	private static void verifyBesWindowStore(String filePath) throws Exception {

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new FileReader(filePath)));
		DOMHelper.useIdAsXmlId(doc.getDocumentElement());

		NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

		//FileSystemDirectoryCertStore certStore = new FileSystemDirectoryCertStore(FOLDERPATH);
		String keyStoreType = "Windows-ROOT";
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(null,null);

		//CertificateValidationProvider provider = new PKIXCertificateValidationProvider(keyStore, false, certStore.getStore());
		CertificateValidationProvider provider = new PKIXCertificateValidationProvider(keyStore, false); 
		XadesVerificationProfile profile = new XadesVerificationProfile(provider);
		Element sigElem = (Element) nl.item(0);
		XAdESVerificationResult r = profile.newVerifier().verify(sigElem, null);

		System.out.println("Signature form: " + r.getSignatureForm());
		System.out.println("Algorithm URI: " + r.getSignatureAlgorithmUri());
		System.out.println("Signed objects: " + r.getSignedDataObjects().size());
		System.out.println("Qualifying properties: " + r.getQualifyingProperties().all().size());

		for (QualifyingProperty qp : r.getQualifyingProperties().all()) {
			if ("SigningCertificate".equals(qp.getName())) {
				Collection<X509Certificate> certs = ((SigningCertificateProperty) qp).getsigningCertificateChain();
				certs.forEach((cert) -> {
					System.out.println("Issuer DN: " + cert.getIssuerDN());
				});
			} else if ("SigningTime".equals(qp.getName())) {
				System.out.println("Time: " + ((SigningTimeProperty) qp).getSigningTime().getTime().toString());
			} else if ("SignatureTimeStamp".equals(qp.getName())) {
				System.out.println("Time stamp: " + ((SignatureTimeStampProperty) qp).getTime().toString());
			} else {
				System.out.println("QP: " + qp.getName());
			}
		}
	}
}
