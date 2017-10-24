
public class Validate {

	//
	// Synopsis: java Validate [document]
	//
	// where "document" is the name of a file containing the XML document
	// to be validated.
	//
//	public static void main(String[] args) throws Exception {
//		String fileName = args[0];
//
//		// Instantiate the document to be validated
//		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//		dbf.setNamespaceAware(true);
//		Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(fileName));
//
//		// Find Signature element
//		NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
//		if (nl.getLength() == 0) {
//			throw new Exception("Cannot find Signature element");
//		}
//
//		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
//		// document containing the XMLSignature
//		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
//
//		// Create a DOMValidateContext and specify a KeyValue KeySelector
//		// and document context
//		DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));
//
//		// unmarshal the XMLSignature
//		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
//
//		// Validate the XMLSignature (generated above)
//		boolean coreValidity = signature.validate(valContext);
//
//		// Check core validation status
//		if (coreValidity == false) {
//			System.err.println("Signature failed core validation");
//			boolean sv = signature.getSignatureValue().validate(valContext);
//			System.out.println("signature validation status: " + sv);
//			// check the validation status of each Reference
//			Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
//			for (int j = 0; i.hasNext(); j++) {
//				boolean refValid = ((Reference) i.next()).validate(valContext);
//				System.out.println("ref[" + j + "] validity status: " + refValid);
//			}
//		} else {
//			System.out.println("Signature passed core validation");
//		}
//	}
//
//	/**
//	 * KeySelector which retrieves the public key out of the KeyValue element
//	 * and returns it. NOTE: If the key algorithm doesn't match signature
//	 * algorithm, then the public key will be ignored.
//	 */
//	private static class KeyValueKeySelector extends KeySelector {
//		public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
//				XMLCryptoContext context) throws KeySelectorException {
//
//			if (keyInfo == null) {
//				throw new KeySelectorException("Null KeyInfo object!");
//			}
//			SignatureMethod sm = (SignatureMethod) method;
//			List<?> list = keyInfo.getContent();
//
//			for (int i = 0; i < list.size(); i++) {
//				XMLStructure xmlStructure = (XMLStructure) list.get(i);
//				if (xmlStructure instanceof X509Data) {
//					PublicKey pk = null;
//					List<?> l = ((X509Data) xmlStructure).getContent();
//					if (l.size() > 0) {
//						X509Certificate cert = (X509Certificate) l.get(0);
//						pk = cert.getPublicKey();
//						if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
//							return new SimpleKeySelectorResult(pk);
//						}
//					}
//				}
//				if (xmlStructure instanceof KeyValue) {
//					PublicKey pk = null;
//					try {
//						pk = ((KeyValue) xmlStructure).getPublicKey();
//					} catch (KeyException ke) {
//						throw new KeySelectorException(ke);
//					}
//					// make sure algorithm is compatible with method
//					if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
//						return new SimpleKeySelectorResult(pk);
//					}
//				}
//			}
//			throw new KeySelectorException("No KeyValue element found!");
//		}
//
//		// @@@FIXME: this should also work for key types other than DSA/RSA
//		static boolean algEquals(String algURI, String algName) {
//			if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
//				return true;
//			} else if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
//				return true;
//			} else {
//				return false;
//			}
//		}
//	}
//
//	private static class SimpleKeySelectorResult implements KeySelectorResult {
//		private PublicKey pk;
//
//		SimpleKeySelectorResult(PublicKey pk) {
//			this.pk = pk;
//		}
//
//		public Key getKey() {
//			return pk;
//		}
//	}

}
