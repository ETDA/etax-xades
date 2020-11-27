
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

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
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.verification.UnexpectedJCAException;

public class XadesBesSigner {

	XadesSigner signer;

	public void setSignerPkcs11(String libPath, String providerName, int slotId, String password) throws Exception {// SigningException
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

			KeyingDataProvider keyingProvider = getKeyingDataProvider(libPath, providerName, slotId, password);
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withAlgorithmsProviderEx(ap);

			signer = p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
	}

	public void setSignerPkcs12(String keyPath, String password, String pkType) throws Exception {// SigningException
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
			KeyingDataProvider keyingProvider = getKeyingDataProvider(keyPath, password, pkType);
			XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
			p.withAlgorithmsProviderEx(ap);

			signer = p.newSigner();
		} catch (Exception ex) {
			throw new Exception("Error " + ex);
		}
	}

	private KeyingDataProvider getKeyingDataProvider(String libPath, String providerName, int slotId, String password)
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableKeyException {

		KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(libPath, providerName, slotId,
				new FirstCertificateSelector(), new DirectPasswordProvider(password), null, false);

		return keyingProvider;
	}

	private KeyingDataProvider getKeyingDataProvider(String keyPath, String password, String pkType)
			throws KeyStoreException, SigningCertChainException, UnexpectedJCAException {
		// P12
		KeyingDataProvider keyingProvider = new FileSystemKeyStoreKeyingDataProvider(pkType, keyPath,
				new FirstCertificateSelector(), new DirectPasswordProvider(password),
				new DirectPasswordProvider(password), false);

		if (keyingProvider.getSigningCertificateChain().isEmpty()) {
			throw new IllegalArgumentException("Cannot initialize keystore with path " + keyPath);
		}
		return keyingProvider;
	}

	/**
	 * Generate the signature and output a single signed file using the enveloped
	 * structure This means that the signature is within the signed XML This method
	 * signs the root node, not an ID
	 * 
	 * @param inputPath
	 * @param outputPath
	 * @throws TransformerFactoryConfigurationError
	 * @throws XAdES4jException
	 * @throws TransformerConfigurationException
	 * @throws TransformerException
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	public void signWithoutIDEnveloped(String inputPath, String outputPath)
			throws TransformerFactoryConfigurationError, XAdES4jException, TransformerConfigurationException,
			TransformerException, IOException, FileNotFoundException {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document sourceDoc = null;

		try {
			sourceDoc = dbf.newDocumentBuilder().parse(inputPath);
		} catch (SAXException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		} catch (ParserConfigurationException ex) {
			// TODO Auto-generated catch block
			ex.printStackTrace();
		}

		FileOutputStream bos = new FileOutputStream(outputPath);

		Element elementToSign = sourceDoc.getDocumentElement();
		String refUri;

		if (elementToSign.hasAttribute("Id")) {
			refUri = '#' + elementToSign.getAttribute("Id");
		} else {
			if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
				bos.close();
				throw new IllegalArgumentException("Element without Id must be the document root.");
			}
			refUri = "";
		}

		DataObjectDesc dataObjRef = new DataObjectReference(refUri).withTransform(new EnvelopedSignatureTransform());

		XadesSignatureResult result = signer.sign(new SignedDataObjects(dataObjRef), sourceDoc.getDocumentElement());
		XMLSignature signature = result.getSignature();
		Document docs = signature.getDocument();

		XMLUtils.outputDOM(docs, bos);
	}

	public XadesBesSigner() {
		signer = null;
	}

}
