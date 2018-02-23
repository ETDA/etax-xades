
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
//import org.apache.log4j.Logger;
//import org.apache.log4j.BasicConfigurator;

public class XadesBesSignMain {

	private static Properties prop;
	private static InputStream config;
	private static String xmlInput;
	private static String xmlOutput;
	private static String pkType;
	private static String pkcs11LibPath;
	private static String pkcs11ProviderName;
	private static int pkcs11SlotId;
	private static String pkcs11Password;
	private static String pkcs12Path;
	private static String pkcs12Password;

	private static final String CONFIG_FILE_PATH = "src/main/resources/conf/etax-xades.properties";

	//static Logger logger = Logger.getLogger(XadesBesSignMain.class);
	
	public static void main(String[] args) {

		//BasicConfigurator.configure();
		
		XadesBesSigner signer = new XadesBesSigner();

		try {
			System.out.println("==============\tSet Signer and its profile\t==============");
			loadConfig(CONFIG_FILE_PATH);

			if (pkType.equals("PKCS11")) {
				// P11 signer
				signer.setSignerPkcs11(pkcs11LibPath, pkcs11ProviderName, pkcs11SlotId, pkcs11Password);
			} else if (pkType.equals("PKCS12")) {
				// P12 signer
				signer.setSignerPkcs12(pkcs12Path, pkcs12Password, pkType);
			} else {
				throw new Exception("PK_TYPE_not_supported");
			}

			System.out.println("==============\tSign\t==============");
			signer.signWithoutIDEnveloped(xmlInput, xmlOutput);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		System.out.println("==============\tFinish\t==============");
	}

	private static void loadConfig(String configPath) {
		try {
			prop = new Properties();
			config = new FileInputStream(configPath);
			// load the properties file
			prop.load(config);

			xmlInput = prop.getProperty("SIGN_INPUT_PATH");
			xmlOutput = prop.getProperty("SIGN_OUTPUT_PATH");
			pkType = prop.getProperty("PK_TYPE");
			pkcs11LibPath = prop.getProperty("PKCS11_LIB_PATH");
			pkcs11ProviderName = prop.getProperty("PKCS11_PROVIDER_NAME");
			pkcs11SlotId = Integer.parseInt(prop.getProperty("PKCS11_SLOT_ID"));
			pkcs11Password = prop.getProperty("PKCS11_PASSWORD");
			pkcs12Path = prop.getProperty("PKCS12_PATH");
			pkcs12Password = prop.getProperty("PKCS12_PASSWORD");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
