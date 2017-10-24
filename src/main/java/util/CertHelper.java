package util;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;
import javax.swing.JOptionPane;

import sun.security.x509.X500Name;

public class CertHelper {

	public CertHelper() {
		// TODO Auto-generated constructor stub
	}

	public X509Certificate[] promptSelectCertDialog() {

		String KEYSTORE_INSTANCE = "Windows-MY";
		try {
			ArrayList<X509Certificate[]> certs = fetchCertificateFromSystemKeyStore(KEYSTORE_INSTANCE);
			// ;X509Certificate[] certs =
			// fetchCertificateFromSystemKeyStore(KEYSTORE_INSTANCE);
			String[] cert_names = new String[certs.size()];
			int i = 0;
			for (X509Certificate[] cert : certs) {
				String tmp = cert[0].getSubjectDN().getName();
				if (tmp.length() > 100) {
					tmp = tmp.substring(0, 100);
					tmp += "...";
				}
				cert_names[i] = tmp;
				i++;
			}
			String selected = (String) JOptionPane.showInputDialog(null, null, "Select a certificate",
					JOptionPane.DEFAULT_OPTION, null, cert_names, cert_names[0]);
			if (selected == null) {
				return null;
			}
			int ansInt = 0;
			for (i = 0; i < cert_names.length; i++) {
				if (cert_names[i].equals(selected)) {
					ansInt = i;
					break;
				}
			}
			return certs.get(ansInt);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;

	}
	
	public ArrayList<X509Certificate[]> fetchCertificateFromSystemKeyStore(String systemType)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = null;
		ArrayList<X509Certificate[]> certificates = new ArrayList<>();
		keyStore = KeyStore.getInstance(systemType);
		keyStore.load(null, null);

		Enumeration<String> alieses = keyStore.aliases();
		String subject = "";
		while (alieses.hasMoreElements()) {
			subject = alieses.nextElement();
			Certificate[] certs = keyStore.getCertificateChain(subject);
			certificates.add((X509Certificate[]) certs);
			// for (int i = 0; i < certs.length; i++) {
			// certificates.add((X509Certificate) certs[i]);
			// }
		}

		return certificates;
		// X509Certificate[] chain = new X509Certificate[certificates.size()];
		// return certificates.toArray(chain);
	}
	
	public String getCNfromX509(X500Principal principal) {
		String cn = principal.getName();
		try {
			X500Name x500name = new X500Name( principal.getName() );
			cn = x500name.getCommonName();
		} catch (Exception e) {
			System.out.println("Cannot get CN from : " + cn);
		}
		return cn;
	}
}
