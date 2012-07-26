package org.megadevs.security.client.db;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.megadevs.security.client.utils.CertificationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Database {

	private static final String DB_NAME = "ClientDB";
	
	private Logger logger;
	
	private Connection mConnection;
	private static Database mInstance;
	
	private Database() {
		logger = LoggerFactory.getLogger(Database.class);
	}

	public static Database getInstance() {
		if (mInstance == null)
			mInstance = new Database();
		
		return mInstance;
	}
	
	/**
	 * Checks if there is any datafile in the current directory (a datafile ends
	 * with the .db extension). If any, it returns true; otherwise, returns false.
	 * 
	 * @return boolean representing the existance of the database
	 */
	public boolean checkDB() {
		File f = new File(DB_NAME + ".db");
		
		if (f.exists())
			return true;
		else
			return false;
	}
	
	public void load() {
		try {
			Class.forName("org.sqlite.JDBC");
			mConnection = DriverManager.getConnection("jdbc:sqlite:" + DB_NAME + ".db");
			Security.addProvider(new BouncyCastleProvider());
			
		} catch (ClassNotFoundException e) {
			logger.error("ClassNotFound when initializing DB", e);
		} catch (SQLException e) {
			logger.error("SQLException when initializing DB", e);
		}
	}
	
	public void init() {
		try {
			load();
			
			Statement stat = mConnection.createStatement();

			String certificates = "create table CERTIFICATES (" +
					"serial integer PRIMARY KEY, " +
					"serial_CA integer, " +
					"not_before datetime, " +
					"not_after datetime, " +
					"subject varchar(256), " +
					"type integer, " +
					"renewed integer, " +
					"certificate blob" +
					");";

			String keypairs = "create table KEYPAIRS (" +
					"serial integer PRIMARY KEY, " +
					"privatekey blob, " +
					"publickey blob, " +
					"keylength integer" +
					");";
			
			String caPassword = "create table CLIENT_PASSWORD (" +
					"hash varchar(32)" +
					");";
			
			String requests = "create table REQUESTS (" +
					"serial integer PRIMARY KEY, " +
					"serial_CA integer," +
					"subject varchar(256), " +
					"type integer," +
					"request blob" +
					");";
			
			String profile = "create table PROFILE (" +
					"surname varchar(256), " +
					"name varchar(256), " +
					"organization varchar(256), " +
					"organizational_unit varchar(256), " +
					"country varchar(256), " +
					"email varchar(256) " +
					");";
			
			String crl = "create table CRL (" +
					"crl blob" +
					");"; 
			
			stat.addBatch(certificates);
			stat.addBatch(requests);
			stat.addBatch(caPassword);
			stat.addBatch(keypairs);
			stat.addBatch(profile);
			stat.addBatch(crl);
			
			int[] result = stat.executeBatch();
			
			for (int i=0; i<result.length; i++) {
				if (result[i] == Statement.EXECUTE_FAILED) {
					logger.error("Issue in initializing DB (statement #" + i + ")");
					System.exit(-1);
				}
			}
			
			stat.close();
			
		} catch (SQLException e) {
			e.printStackTrace();
			logger.error("SQLException when initializing DB", e);
		}
	}
	
	public void storeClientPassword(String password) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into CLIENT_PASSWORD values (?);");

			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] thedigest = md.digest(password.getBytes());
			String hash = new String(thedigest);
			stat.setString(1, hash);

			stat.execute();
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (client password)", e);
			}
		}
	}
	
	public void storeProfile(String surname, String name, String organization, 
			String organizationalUnit, String country, String email) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into PROFILE values (?, ?, ?, ?, ?, ?);");

			stat.setString(1, surname);
			stat.setString(2, name);
			stat.setString(3, organization);
			stat.setString(4, organizationalUnit);
			stat.setString(5, country);
			stat.setString(6, email);
			
			stat.execute();
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving client profile", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (client profile)", e);
			}
		}
	}
	
	public int storeKeyPair(String password, KeyPair key, Integer keyLength) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into KEYPAIRS values (?, ?, ?, ?);");

			Charset charSet = Charset.forName("UTF-8");
			byte[] keyBytes = key.getPrivate().getEncoded();
			byte[] passBytes = password.getBytes(charSet);
			
			byte[] cipherBytes = new byte[keyBytes.length];
			for (int i = 0; i < keyBytes.length; i++) 
			    cipherBytes[i] = (byte) (keyBytes[i] ^ passBytes[i % passBytes.length]);
			
			stat.setBytes(2, cipherBytes);
			stat.setBytes(3, key.getPublic().getEncoded());
			stat.setInt(4, keyLength);
			stat.execute();
			
			stat = mConnection.prepareStatement("select last_insert_rowid() as ID;");
			ResultSet result = stat.executeQuery();
			if (result.next())
				return result.getInt(1);
			
		} catch (SQLException e) {
			e.printStackTrace();
			logger.error("SQLException when retrieving client properties", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (client properties)", e);
			}
		}
		return -1;
	}
	
	public void storeCertificateRequest(int serial, PKCS10CertificationRequest request) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into REQUESTS values (?, ?, ?, ?, ?);");

			stat.setInt(1, serial);
			stat.setInt(2, -1);
			stat.setString(3, request.getSubject().toString());
			
	        Vector<ASN1ObjectIdentifier> oidSS = new Vector<ASN1ObjectIdentifier>();
            Vector<Extension> values = new Vector<Extension>();
           
            Attribute[] list = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (list.length >= 1) {
            	Extensions ext = Extensions.getInstance(list[0].getAttrValues().getObjectAt(0));
            	ASN1ObjectIdentifier[] obid = ext.getExtensionOIDs();
                for(int i=0;i<obid.length;i++) {
                	oidSS.add(obid[i]);
                    values.add(ext.getExtension(obid[i]));
                }
            }
           
            ASN1InputStream is = new ASN1InputStream(values.get(0).getExtnValue().getOctetStream());
            KeyUsage keyusage = new KeyUsage((DERBitString) is.readObject());
            stat.setInt(4, keyusage.intValue());
			
			stat.setBytes(5, request.getEncoded());

			stat.execute();
			
		} catch (SQLException e) {
			logger.error("SQLException when storing certificate request", e);
		} catch (IOException e) {
			logger.error("IOException when storing certificate request", e);
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate request)", e);
			}
		}
	}
	
	public void storeCertificate(Integer serial, Integer serialCA, X509CertificateHolder cert) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("insert into CERTIFICATES values (?, ?, ?, ?, ?, ?, ?, ?);");

			stat.setInt(1, serial);
			stat.setInt(2, serialCA);
			stat.setDate(3,	new Date(cert.getNotBefore().getTime()));
			stat.setDate(4,	new Date(cert.getNotAfter().getTime()));
			stat.setString(5, cert.getSubject().toString());

			X509Certificate certificate = CertificationUtils.getCertificateFromHolder(cert);
			stat.setInt(6, certificate.getKeyUsage()[0] ? KeyUsage.digitalSignature : KeyUsage.dataEncipherment);
			stat.setInt(7, -1);
			stat.setBytes(8, certificate.getEncoded());
			
			stat.execute();
			stat.close();
			
		} catch (SQLException e) {
			logger.error("SQLException when storing certificate request", e);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate request)", e);
			}
		}
	}
	
	public void storeCRL(X509CRLHolder crl) {
		PreparedStatement stat = null;
			try {
				stat = mConnection.prepareStatement("insert into CRL values (?);");
				stat.setBytes(1, crl.getEncoded());
				stat.execute();
				
			} catch (SQLException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			finally {
				try {
					stat.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}

	}
	
	public boolean checkPassword(String password) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CLIENT_PASSWORD;");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				String hash = result.getString(1);
				
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] thedigest = md.digest(password.getBytes());
				String passHash = new String(thedigest);

				return hash.equals(passHash);
			}
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
		return false;
	}
	
	public ArrayList<String> getProfile() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from PROFILE;");
			
			ArrayList<String> list = new ArrayList<String>();
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				list.add(result.getString(1));
				list.add(result.getString(2));
				list.add(result.getString(3));
				list.add(result.getString(4));
				list.add(result.getString(5));
				list.add(result.getString(6));
			}
			
			return list;
			
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		
		return null;
	}
	
	public KeyPair getKeyPair(Integer serial, String password) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from KEYPAIRS where serial=" + String.valueOf(serial.intValue()) + ";");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next()) {
				byte[] cipherBytes = result.getBytes(2);
				Charset charSet = Charset.forName("UTF-8");
				byte[] passBytes = password.getBytes(charSet);
				byte[] plainBytes = new byte[cipherBytes.length];
				
				for (int i = 0; i < cipherBytes.length; i++)
				    plainBytes[i] = (byte) (cipherBytes[i] ^ passBytes[i % passBytes.length]);

				KeySpec privateSpecs = new PKCS8EncodedKeySpec(plainBytes);
				X509EncodedKeySpec publicSpecs = new X509EncodedKeySpec(result.getBytes(3));
		        PrivateKey privateKey = KeyFactory.getInstance("RSA", "BC").generatePrivate(privateSpecs);
		        PublicKey publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(publicSpecs);
		        
		        return new KeyPair(publicKey, privateKey);
			}

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate)", e);
			}
		}
		
		return null;
	}
	
	public Integer getKeyLengthFromKeyPair(Integer serial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from KEYPAIRS where serial=" + String.valueOf(serial.intValue()) + ";");
			
			ResultSet result = stat.executeQuery();
			
			if (result.next())
				return result.getInt(4);
			

		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (keylength)", e);
			}
		}
		
		return null;
	}

	
	public X509CertificateHolder getCertificate(Integer serial) {

		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CERTIFICATES where serial=" + String.valueOf(serial.intValue()) + ";");

			ResultSet result = stat.executeQuery();

			if (result.next()) {
				byte[] b = result.getBytes(8);
				ByteArrayInputStream in = new ByteArrayInputStream(b);
				X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);
				return new X509CertificateHolder(cert.getEncoded());
			}

		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate ", e);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificate)", e);
			}
		}

		return null;
	}

	public ArrayList<X509CertificateHolder> getCertificatesList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CERTIFICATES;");

			ResultSet result = stat.executeQuery();

			ArrayList<X509CertificateHolder> list = new ArrayList<X509CertificateHolder>();

			while (result.next()) {
				byte[] b = result.getBytes(8);
				ByteArrayInputStream in = new ByteArrayInputStream(b);
				X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in);
				list.add(new X509CertificateHolder(cert.getEncoded()));
			}

			return list;

		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificates list", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificates list", e);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certificates list)", e);
			}
		}

		return null;

	}
	
	public PKCS10CertificationRequest getCertificateRequest(Integer serial) {
		
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS where serial=" + String.valueOf(serial.intValue()) + ";");
			
			ResultSet result = stat.executeQuery();

			if (result.next()) {
				byte[] b = result.getBytes(5);
				return new PKCS10CertificationRequest(b);
			}
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate request", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate request", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification request)", e);
			}
		}
		
		return null;
	}
	
	public ArrayList<PKCS10CertificationRequest> getCertificateRequestsList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS;");
			
			ResultSet result = stat.executeQuery();

			ArrayList<PKCS10CertificationRequest> list = new ArrayList<PKCS10CertificationRequest>();
			
			while (result.next()) {
				byte[] b = result.getBytes(5);
				list.add(new PKCS10CertificationRequest(b));
			}
			
			return list;
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate requests list", e);
		} catch (IOException e) {
			logger.error("IOException when retrieving certificate requests list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification requests list)", e);
			}
		}
		
		return null;

	}

	public Integer getSerialCAFromCertificateRequests(Integer serial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS where serial="+ String.valueOf(serial.intValue()) + ";");
			
			ResultSet result = stat.executeQuery();

			if (result.next())
				return result.getInt(2);
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate requests list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification requests list)", e);
			}
		}
		
		return null;
	}
	
	public ArrayList<Integer[]> getCertificateRequestsDetailsList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from REQUESTS;");

			ResultSet result = stat.executeQuery();

			ArrayList<Integer[]> list = new ArrayList<Integer[]>();
			
			while (result.next()) {
				Integer serial = result.getInt(1);
				Integer serialCA = result.getInt(2);
				Integer type = result.getInt(4);
				list.add(new Integer[] {serial, serialCA, type});
			}
			
			return list;
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate requests list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification requests list)", e);
			}
		}
		
		return null;

	}

	public ArrayList<Object[]> getCertificatesDetailsList() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CERTIFICATES;");
			
			ResultSet result = stat.executeQuery();

			ArrayList<Object[]> list = new ArrayList<Object[]>();
			
			while (result.next()) {
				Integer serial = result.getInt(1);
				Integer serialCA = result.getInt(2);
				Date before = result.getDate(3);
				Date after = result.getDate(4);
				String subject = result.getString(5);
				Integer type = result.getInt(6);
				Integer renewed = result.getInt(7);
				list.add(new Object[] {serial, serialCA, before, after, subject, type, renewed});
			}
			
			return list;
			
		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate requests list", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification requests list)", e);
			}
		}
		
		return null;

	}

	
	public void updateCertificationRequestSerial(Integer serialCA, Integer serial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("update REQUESTS set serial_CA = " + serialCA.toString() + " where serial = " + serial.toString() + ";");
			stat.execute();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
	
	public X509CRLHolder getCRL() {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("select * from CRL;");

			ResultSet result = stat.executeQuery();
			if (result.next())
				return new X509CRLHolder(result.getBytes(1));
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}

		return null;
	}
	
	public void updateCRL(X509CRLHolder crl) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("update CRL set crl=?");
			stat.setBytes(1, crl.getEncoded());
			stat.execute();
			
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

	public void deleteCertificateRequest(Integer serial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("delete from REQUESTS where serial=" + String.valueOf(serial.intValue()) + ";");
			stat.execute();

		} catch (SQLException e) {
			logger.error("SQLException when retrieving certificate request", e);
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				logger.error("SQLException when closing statement (certification request)", e);
			}
		}
	}

	public void updateCertificateUponRenewal(Integer serial, Integer renewedSerial) {
		PreparedStatement stat = null;
		try {
			stat = mConnection.prepareStatement("update CERTIFICATES set renewed = " + renewedSerial.toString() + " where serial = " + serial.toString() + ";");
			stat.execute();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		finally {
			try {
				stat.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

}
