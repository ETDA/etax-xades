
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
//import org.apache.log4j.Logger;
//import org.apache.log4j.BasicConfigurator;

public class XadesBesVerifyMain {

	private static Properties prop;
	private static InputStream config;

	private static String verifyInput;
	private static String trustStoreType;
	private static String trustStorePath;
	private static String trustStorePassword;
	private static String certStoreDir;

	private static final String CONFIG_FILE_PATH = "src/main/resources/conf/etax-xades.properties";
	
	//static Logger logger = Logger.getLogger(XadesBesVerifyMain.class);
	
	public static void main(String[] args) {

		//BasicConfigurator.configure();
		
		XadesBesVerifier verifier = new XadesBesVerifier();
		try {
			System.out.println("==============\tVerify\t==============");
			loadConfig(CONFIG_FILE_PATH);

			verifier.verifyBes(verifyInput, trustStoreType, trustStorePath, trustStorePassword, certStoreDir);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("==============\tFinish\t==============");
	}

	private static void loadConfig(String configPath) {
		try {
			prop = new Properties();
			config = new FileInputStream(configPath);
			// load the properties file
			prop.load(config);

			verifyInput = prop.getProperty("VERIFY_INPUT_PATH");
			trustStoreType = prop.getProperty("TRUST_STORE_TYPE");
			trustStorePath = prop.getProperty("TRUST_STORE_PATH");
			trustStorePassword = prop.getProperty("TRUST_STORE_PASSWORD");
			certStoreDir = prop.getProperty("CERT_STORE_DIR");

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
