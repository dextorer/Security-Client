package org.megadevs.security.client;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.megadevs.security.client.db.Database;
import org.megadevs.security.client.pdf.PDFUtils;
import org.megadevs.security.client.ui.UI;
import org.megadevs.security.client.utils.CertificationUtils;
import org.megadevs.security.client.utils.NetworkUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.CertificateInfo;

public class Client {

	public Database mDatabase;
	private UI mUI;
	
	public String mPassword;
	
	private Logger logger;
	
	public void setup() {
		Security.addProvider(new BouncyCastleProvider());
		logger = LoggerFactory.getLogger(Client.class);
		mDatabase = Database.getInstance();
		
		if (checkDB())
			mUI = new UI(this, true);
		else mUI = new UI(this, false);
	}
	
	public void init() throws Exception {
		getCRLFromCA();
	}
	
	private void initializeCRL(KeyPair keyPair) {
		try {
			X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name("CN=dummy_CRL"), new Date());
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
			X509CRLHolder crlHolder = crlBuilder.build(sigGen);
			
			mDatabase.storeCRL(crlHolder);
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}
	}
	
	private boolean checkDB() {
		
		boolean exists = mDatabase.checkDB();
		if (exists)
			mDatabase.load();
		else mDatabase.init();
		
		return exists;
	}
	
	public boolean checkPassword(String password) {
		boolean isValid = mDatabase.checkPassword(password);
		if (isValid) 
			mPassword = password;
		
		return isValid;
	}
	
	public void setAndStoreClientPassword(String password) {
		mDatabase.storeClientPassword(password);
		mPassword = password;
	}
	
	
	public void storeClientInfo(String surname, String name, String organization, 
			String organizationalUnit, String country, String email) {
		mDatabase.storeProfile(surname, name, organization, organizationalUnit, country, email);
	}

	
	public ArrayList<String> getClientInfo() {
		return mDatabase.getProfile();
	}
	
	
	public void createFirstRequest(String length) {
		int serial = generateCertificateRequest(length, new KeyUsage(KeyUsage.digitalSignature));
		initializeCRL(mDatabase.getKeyPair(serial, mPassword));
	}
	
	
	public Integer generateCertificateRequest(String keyLength, KeyUsage usage) {

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(Integer.parseInt(keyLength), new SecureRandom());
			KeyPair keyPairForRequest = generator.generateKeyPair();

			KeyPair keyPairForSignature = null;
			if (usage.intValue() == KeyUsage.dataEncipherment) {
				Integer id = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
				keyPairForSignature = mDatabase.getKeyPair(id, mPassword);
			} else {
				keyPairForSignature = keyPairForRequest;
			}
			
			int serial = mDatabase.storeKeyPair(mPassword, keyPairForRequest, Integer.valueOf(keyLength));
			
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");

			SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(keyPairForRequest.getPublic().getEncoded());
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPairForRequest.getPrivate());

			Extension[] values = new Extension[] {new Extension(Extension.keyUsage, true, new DEROctetString(usage))};
	        Extensions extensions = new Extensions(values);
	        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
			
			CertificationRequestInfo info = new CertificationRequestInfo(new X500Name(profileToDN(mDatabase.getProfile())), key, new DERSet(attribute));
			PKCS10CertificationRequest newRequest = new PKCS10CertificationRequest(new CertificationRequest(info, sigAlgId, new DERBitString(sigGen.getSignature())));

			String encodedString = new String(Base64.encode(newRequest.getEncoded()));
			
			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPairForSignature);
			
			String response = NetworkUtils.sendMessageToServer(signedXML, "newCertificateRequest");
			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");
				
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));
				
				NodeList nodes = doc.getElementsByTagName("content");
				
				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				String decodedContent = new String(Base64.decode(content.getBytes()));
				
				if (Integer.valueOf(decodedContent) != -1) {
					logger.info("Updating certification request index in database, value is " + decodedContent);
					mDatabase.storeCertificateRequest(serial, newRequest);//TODO vedere se rimuoverne una
					mDatabase.updateCertificationRequestSerial(new Integer(decodedContent), serial);
				}
				else {
					logger.error("Server response is -1: bad certification request procedure. Aborting.");
					System.exit(-1);
				}
			} else {
				logger.error("Invalid server response signature. Aborting.");
				System.exit(-1);
			}

			return serial;
			
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	public Integer checkCertificateRequest(Integer serial) {
		try {
			KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature);

			Integer activeCertificate = getActiveCertificate(usage, true);
			if (activeCertificate == null) {
				mUI.noValidDigitalSignatureCertificate();
				return null;
			}

			KeyPair keyPair = mDatabase.getKeyPair(activeCertificate, mPassword);
			Integer serialCA = mDatabase.getSerialCAFromCertificateRequests(serial);//TODO inutile
			
			String encodedString = new String(Base64.encode(String.valueOf(serialCA.intValue()).getBytes()));

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "checkCertificateRequest");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");

				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				System.out.println(content);

				if (content.startsWith("[REQ"))
					System.out.println(content);
				else {
					X509CertificateHolder holder = new X509CertificateHolder(Base64.decode(content.getBytes()));
					mDatabase.deleteCertificateRequest(serial);
					mDatabase.storeCertificate(serial, serialCA, holder);
					return serial;
				}
			} else {
				logger.error("Invalid server response signature. Aborting.");
				System.exit(-1);
			}

		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public void getCRLFromCA() throws Exception {
		try {
			String encodedString = new String(Base64.encode("".getBytes()));
			Integer ID = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), true);
			if (ID == null)
				throw new Exception();
			
			KeyPair keyPair = mDatabase.getKeyPair(ID, mPassword);

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "getCRL");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				
				X509CRLHolder crl = new X509CRLHolder(Base64.decode(content.getBytes()));
				mDatabase.updateCRL(crl);
			}
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private X509CertificateHolder getRootCertificate() {
		try {
			String encodedString = new String(Base64.encode("".getBytes()));
			Integer ID = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), true);
			KeyPair keyPair = mDatabase.getKeyPair(ID, mPassword);

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "getRootCertificate");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				
				X509CertificateHolder root = new X509CertificateHolder(Base64.decode(content.getBytes()));
				return root;
			}
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	
	public ArrayList<X509CertificateHolder> getActiveDataEnciphermentCertificates() {
		try {
			String encodedString = new String(Base64.encode("".getBytes()));
			Integer ID = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), true);
			KeyPair keyPair = mDatabase.getKeyPair(ID, mPassword);

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "getActiveDataEnciphermentCertificates");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				
				if (content.length() > 1) {
					String[] split = (new String(Base64.decode(content.getBytes()))).split(":");
					
					ArrayList<X509CertificateHolder> result = new ArrayList<X509CertificateHolder>();
					
					for (String s : split)
						result.add(new X509CertificateHolder(Base64.decode(s.getBytes())));
					
					return result;
				}
			}
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	
	private String profileToDN(ArrayList<String> list) {
		String surname = list.get(0);
		String name = list.get(1);
		String organization = list.get(2);
		String organizationalUnit = list.get(3);
		String country = list.get(4);
		String email = list.get(5);
		
		StringBuilder builder = new StringBuilder();
		builder.append("C="+country);
		builder.append(", O="+organization);
		builder.append(", OU="+organizationalUnit);
		builder.append(", CN="+surname+" "+name+" "+email);
		
		return builder.toString();
	}
	
	public HashMap<String, String> DNToProfile(String dn) {
		String[] split = dn.split(",");
		
		HashMap<String, String> result = new HashMap<String, String>();
		
		for (String s : split) {
			String[] both = s.trim().split("=");
			if (both[0].compareTo("CN") == 0) { // no double names allowed (lol)
				String[] cn = both[1].split(" "); // splitting CN to get surname, name and email
				result.put("SURNAME", cn[0]);
				result.put("NAME", cn[1]);
				result.put("EMAIL", cn[2]);
			}
			else result.put(both[0], both[1]);
		}
		
		return result;
	}
	
	
	public Integer getActiveCertificate(KeyUsage usage, boolean fallback) {
		ArrayList<Object[]> list = mDatabase.getCertificatesDetailsList();
		X509CRLHolder crl = mDatabase.getCRL();
		
		Integer ID = null;
//		Date notBefore = new Date();
		
		for (Object[] current : list) {
			Date now = new Date();
			if (now.before((Date) current[3]) && now.after((Date) current[2]) && ((Integer) current[5]).intValue() == usage.intValue() && (((Integer) current[6]).intValue() == -1)) {
				if (crl.getRevokedCertificate(new BigInteger(((Integer) current[1]).toString())) == null) {
					Integer currentID = new Integer(((Integer) current[0]).intValue());
//					Date date = (Date) current[3];
//					if (date.after(notBefore)) { // need to return the most recent certificate
						ID = currentID;
//						notBefore = date;
//					}
				}
			}
		}

		if (fallback) {
			ArrayList<Integer[]> details = mDatabase.getCertificateRequestsDetailsList();
			for (Integer[] request : details)
				if (request[2].intValue() == usage.intValue()) {
					return request[0];
				}
		}
		
		return ID;
	}
	
	private boolean checkCertificateWithOCSP(Integer ID) {

		try {
			DigestCalculatorProvider provider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
			X509CertificateHolder holder = mDatabase.getCertificate(ID);
			
			OCSPReqBuilder builder = new OCSPReqBuilder();
			builder.addRequest(new CertificateID(provider.get(CertificateID.HASH_SHA1), holder, holder.getSerialNumber()));
			builder.setRequestorName(new X500Name(profileToDN(mDatabase.getProfile())));

			Integer activeCertificateID = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
			KeyPair keyPair = mDatabase.getKeyPair(activeCertificateID, mPassword);
			
			OCSPReq OCSPRequest = builder.build();
			
			String encodedString = new String(Base64.encode(OCSPRequest.getEncoded()));

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "checkCertificateWithOCSP");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");

				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);

				OCSPResp ocspResponse = new OCSPResp(Base64.decode(content));
				BasicOCSPResp responseObject = (BasicOCSPResp) ocspResponse.getResponseObject();
				SingleResp[] responses = responseObject.getResponses();
				
				for (SingleResp resp : responses)
					if (resp.getCertStatus() != null)
						return false;
				
				return true;
			}
			
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (OCSPException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		}
		
		
		return false;
	}

	public String revokeCertificate(Integer ID) {
		try {
			KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature);

			Integer activeCertificate = getActiveCertificate(usage, true);
			if (activeCertificate == null) {
				mUI.noValidDigitalSignatureCertificate();
				return null;
			}

			KeyPair keyPair = mDatabase.getKeyPair(activeCertificate, mPassword);

			String encodedString = new String(Base64.encode(ID.toString().getBytes()));

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "revokeCertificate");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");

				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				System.out.println(content);
				return content;

			} else {
				logger.error("Invalid server response signature. Aborting.");
				System.exit(-1);
			}

		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public Integer renewCertificate(Integer ID) {
		try {
			X509CertificateHolder oldCertificate = mDatabase.getCertificate(ID);
			ByteArrayInputStream in = new ByteArrayInputStream(oldCertificate.getEncoded());
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in); 

			KeyUsage usage = null;
			if (certificate.getKeyUsage()[0])
				usage = new KeyUsage(KeyUsage.digitalSignature);
			else usage = new KeyUsage(KeyUsage.dataEncipherment);

			Integer activeCertificate = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), true);
			if (activeCertificate == null) {
				mUI.noValidDigitalSignatureCertificate();
				return -1;
			}

			Integer keyLength = mDatabase.getKeyLengthFromKeyPair(ID);
			
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(keyLength, new SecureRandom());
			KeyPair keyPairForRequest = generator.generateKeyPair();

			int serial = mDatabase.storeKeyPair(mPassword, keyPairForRequest, Integer.valueOf(keyLength));
			
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");

			SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(keyPairForRequest.getPublic().getEncoded());
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPairForRequest.getPrivate());

			Extension[] values = new Extension[] {new Extension(Extension.keyUsage, true, new DEROctetString(usage))};
	        Extensions extensions = new Extensions(values);
	        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
			
			CertificationRequestInfo info = new CertificationRequestInfo(new X500Name(profileToDN(mDatabase.getProfile())), key, new DERSet(attribute));
			PKCS10CertificationRequest newRequest = new PKCS10CertificationRequest(new CertificationRequest(info, sigAlgId, new DERBitString(sigGen.getSignature())));

			mDatabase.storeCertificateRequest(serial, newRequest);
			
			KeyPair keyPair = mDatabase.getKeyPair(activeCertificate, mPassword);
			String encodedString = new String(Base64.encode(newRequest.getEncoded()));

			String prepareXMLMessage = NetworkUtils.prepareXMLMessage(encodedString);
			String signedXML = NetworkUtils.generateXMLSignature(prepareXMLMessage, keyPair);
			String response = NetworkUtils.sendMessageToServer(signedXML, "renewCertificate");

			boolean isValid = NetworkUtils.validateXMLSignature(response);
			if (isValid) {
				logger.info("Valid XML signature in certification request response from server.");

				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				DocumentBuilder db = dbf.newDocumentBuilder();
				Document doc = db.parse(new InputSource(new StringReader(response)));

				NodeList nodes = doc.getElementsByTagName("content");

				Element element = (Element) nodes.item(0);
				String content = NetworkUtils.getCharacterDataFromElement(element);
				
				if (content.startsWith("-1"))
					System.out.println(content);
				else {
					X509CertificateHolder holder = new X509CertificateHolder(Base64.decode(content.getBytes()));
					mDatabase.deleteCertificateRequest(serial);
					Integer renewedSerial = holder.getSerialNumber().intValue();
					mDatabase.storeCertificate(serial, renewedSerial, holder);
					mDatabase.updateCertificateUponRenewal(ID, renewedSerial);
					
					return renewedSerial;
				}


			} else {
				logger.error("Invalid server response signature. Aborting.");
				System.exit(-1);
			}

		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		return -1;
	}
	
	public ArrayList<PKCS10CertificationRequest> getCertificationRequestsList() {
		return mDatabase.getCertificateRequestsList();
	}

	public X509CRLHolder getCRLFromDatabase() {
		return mDatabase.getCRL();
	}

	public ArrayList<Integer[]> getCertificationRequestsDetailsList() {
		return mDatabase.getCertificateRequestsDetailsList();
	}
	
	public ArrayList<Object[]> getCertificatesDetailsList() {
		return mDatabase.getCertificatesDetailsList();
	}
	
	public static void main(String[] args) {
		Client c = new Client();
		c.setup();
	}

	@SuppressWarnings("deprecation")
	public void signPDF(String path) throws Exception {
		PdfReader reader = new PdfReader(path);
		FileOutputStream os = new FileOutputStream(path.replace(".pdf", "-signed.pdf"));
		PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

		Integer activeCertificate = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
		if (activeCertificate == null || !checkCertificateWithOCSP(activeCertificate))
			throw new Exception("Invalid certificate (OCSP check)");
		
		KeyPair keyPair = mDatabase.getKeyPair(activeCertificate, mPassword);

		X509CertificateHolder x509Certificate = mDatabase.getCertificate(activeCertificate);
		CertificateFactory instance = CertificateFactory.getInstance("X.509", "BC");
		ByteArrayInputStream bais = new ByteArrayInputStream(x509Certificate.getEncoded());
		Certificate certificate = instance.generateCertificate(bais);
		
		PdfSignatureAppearance sap = stamper.getSignatureAppearance();
//        sap.setVisibleSignature(new Rectangle(72, 732, 144, 780), 1, null);
        sap.setSignDate(new GregorianCalendar());
        Image image = Image.getInstance(Client.class.getResource("/logo_unipd.jpg"));
		sap.setImage(image);
		sap.setReason("Security Project - Universita' degli Studi di Padova");
		sap.setLocation("Padova");
		int offset = 20;
		Rectangle pageSize = reader.getPageSize(1);
		sap.setVisibleSignature(new Rectangle(pageSize.getWidth()-offset-image.getWidth()/7, offset, pageSize.getWidth()-offset, offset + image.getHeight()/7), 1, null);
//        finder.getLlx(), finder.getLly(),finder.getWidth(), finder.getHeight()
        sap.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        sap.setCertificate(certificate);
        PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);
        dic.setDate(new PdfDate(sap.getSignDate()));
        dic.setName(CertificateInfo.getSubjectFields(CertificationUtils.getCertificateFromHolder(x509Certificate)).getField("CN"));
        dic.setReason("Signed with BC");
        dic.setLocation("Foobar");
        sap.setCryptoDictionary(dic);
        int csize = 4000;
        HashMap<PdfName,Integer> exc = new HashMap<PdfName,Integer>();
        exc.put(PdfName.CONTENTS, new Integer(csize * 2 + 2));
        sap.preClose(exc);
        // signature
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
        generator.addSignerInfoGenerator(
                  new JcaSignerInfoGeneratorBuilder(
                       new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                       .build(sha1Signer, x509Certificate));

        ArrayList<Certificate> list = new ArrayList<Certificate>();
        list.add(CertificationUtils.getCertificateFromHolder(x509Certificate));
        CertStore chainStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(list), "BC");
        generator.addCertificatesAndCRLs(chainStore);
        CMSSignedData signedData;

        MessageDigest md = MessageDigest.getInstance("SHA1");
        InputStream s = sap.getRangeStream();
        int read = 0;
        byte[] buff = new byte[8192];
        while ((read = s.read(buff, 0, 8192)) > 0) {
        	md.update(buff, 0, read);
        }
        CMSProcessableByteArray content = new CMSProcessableByteArray(md.digest());
        signedData = generator.generate(content);
        byte[] pk = signedData.getEncoded();
        
        byte[] outc = new byte[csize];
        PdfDictionary dic2 = new PdfDictionary();
        System.arraycopy(pk, 0, outc, 0, pk.length);
        dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
        sap.close(dic2);
	}

	public void verifyPDF(String path) {
		Integer activeCertificate = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
//		try {
//			X509Certificate cert1 = CertificationUtils.getCertificateFromHolder(getRootCertificate());
//			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//			ks.load(null, null);
//			ks.setCertificateEntry("cacert", cert1);
//
//			PdfReader reader = new PdfReader(path);
//			AcroFields af = reader.getAcroFields();
//			ArrayList<String> names = af.getSignatureNames();
//			for (String name : names) {
//				System.out.println("Signature name: " + name);
//				System.out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
//				System.out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
//				PdfPKCS7 pk = af.verifySignature(name);
//				Calendar cal = pk.getSignDate();
//				Certificate[] pkc = pk.getCertificates();
//				System.out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
//				System.out.println("Revision modified: " + !pk.verify());
//				Object fails[] = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
//				if (fails == null)
//					System.out.println("Certificates verified against the KeyStore");
//				else
//					System.out.println("Certificate failed: " + fails[1]);    
//			}
//			
//		} catch (KeyStoreException e) {
//			e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		} catch (CertificateException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (SignatureException e) {
//			e.printStackTrace();
//		}
		
//		System.out.println(PDFUtils.verifyPDFsignature(path, mDatabase.getCertificate(activeCertificate), getRootCertificate()));
	}

	public String encryptPDF(String path, String type, X509CertificateHolder certificate) {
		String result = "";
		int encryptionType = -1;

		if (type.contains("AES-128")) encryptionType = PdfWriter.ENCRYPTION_AES_128;
		else if (type.contains("AES-256")) encryptionType = PdfWriter.ENCRYPTION_AES_256;
		else if (type.contains("ARC4-40")) encryptionType = PdfWriter.STANDARD_ENCRYPTION_40;
		else if (type.contains("ARC4-128")) encryptionType = PdfWriter.STANDARD_ENCRYPTION_128;
		
		try {
			PdfReader reader = new PdfReader(path);
			FileOutputStream os = new FileOutputStream(path.replace(".pdf", "-encrypted.pdf"));
			PdfStamper stamper = new PdfStamper(reader, os);
			
			CertificateFactory instance = CertificateFactory.getInstance("X.509", "BC");
			ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
			Certificate cert = instance.generateCertificate(bais);
			
			stamper.setEncryption(new Certificate[] {cert}, new int[] {PdfWriter.ALLOW_PRINTING}, encryptionType);
			stamper.close();
			result = "PDF correctly encrypted";
			
		} catch (IOException e) {
			e.printStackTrace();
			result = "Error in PDF encryption! " + e.getMessage();
		} catch (DocumentException e) {
			e.printStackTrace();
			result = "Error in PDF encryption! " + e.getMessage();
		} catch (CertificateException e) {
			e.printStackTrace();
			result = "Error in PDF encryption! " + e.getMessage();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			result = "Error in PDF encryption! " + e.getMessage();
		} catch (Exception e) {
			e.printStackTrace();
			result = "Error in PDF encryption! " + e.getMessage();
		}
		
		return result + "!";
	}

	public String decryptPDF(String path, Integer iD) {
		return PDFUtils.decryptPDF(this, path, iD);
	}
	
	public void updateCRL() {
		try {
			getCRLFromCA();
			mUI.getCrlPanel().updateData();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
/*
 * 
	public void signPDF(String path) throws Exception {
		try {
			PdfReader reader = new PdfReader(path);
			FileOutputStream os = new FileOutputStream(path.replace(".pdf", "-signed.pdf"));
			PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

			PdfSignatureAppearance sap = stamper.getSignatureAppearance();
//			sap.setImage(Image.getInstance("./res/logo_unipd.jpg"));
			sap.setReason("Security Project - Universita' degli Studi di Padova");
			sap.setLocation("Foobar");
			sap.setVisibleSignature(new Rectangle(10, 460, 457, 10), 1, "Test");
			
			Integer activeCertificate = getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
			if (activeCertificate == null || !checkCertificateWithOCSP(activeCertificate))
				throw new Exception("Invalid certificate (OCSP check)");
			
			KeyPair keyPair = mDatabase.getKeyPair(activeCertificate, mPassword);

			X509CertificateHolder x509Certificate = mDatabase.getCertificate(activeCertificate);
			CertificateFactory instance = CertificateFactory.getInstance("X.509", "BC");
			ByteArrayInputStream bais = new ByteArrayInputStream(x509Certificate.getEncoded());
			Certificate certificate = instance.generateCertificate(bais);

			X509EncodedKeySpec spec = new X509EncodedKeySpec(getRootCertificate().getSubjectPublicKeyInfo().parsePublicKey().getEncoded());
			PublicKey publicKey = KeyFactory.getInstance("RSA", "BC").generatePublic(spec);
			certificate.verify(publicKey);
			
			ExternalSignature es = new PrivateKeySignature(keyPair.getPrivate(), "SHAWithRSA", "BC");
			MakeSignature.signDetached(null, es, new Certificate[] {certificate}, null, null, null, null, 0, MakeSignature.CADES);
			
			System.out.println("after");
			
			bais.close();
			stamper.close();
			
			System.out.println("end");
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (DocumentException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}

 */
