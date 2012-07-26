package org.megadevs.security.client.pdf;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;

import org.bouncycastle.cert.X509CertificateHolder;
import org.megadevs.security.client.Client;

import com.itextpdfrevisited.text.DocumentException;
import com.itextpdfrevisited.text.pdf.PdfReader;
import com.itextpdfrevisited.text.pdf.PdfStamper;
import com.megadevs.itextpdfwrapper.ITextPDFWrapper;

public class PDFUtils {
	public static String decryptPDF(Client client, String path, Integer ID) {
		String result = "";
		
		try {
			X509CertificateHolder certificate = client.mDatabase.getCertificate(ID);
			KeyPair keyPair = client.mDatabase.getKeyPair(ID, client.mPassword);
			
			CertificateFactory instance = CertificateFactory.getInstance("X.509", "BC");
			ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
			Certificate cert = instance.generateCertificate(bais);

			PdfReader reader = ITextPDFWrapper.getInitializedReader(path, cert, keyPair.getPrivate(), "BC");
			FileOutputStream os = new FileOutputStream(path.replace(".pdf", "-decrypted.pdf"));
			PdfStamper stamper = new PdfStamper(reader, os);
			
			stamper.close();
			result = "PDF correctly decrypted!";
			
		} catch (IOException e) {
			e.printStackTrace();
			result = "Error in PDF decryption! " + e.getMessage();
		} catch (DocumentException e) {
			e.printStackTrace();
			result = "Error in PDF decryption! " + e.getMessage();
		} catch (CertificateException e) {
			e.printStackTrace();
			result = "Error in PDF decryption! " + e.getMessage();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			result = "Error in PDF decryption! " + e.getMessage();
		} catch (Exception e) {
			e.printStackTrace();
			result = "Error in PDF decryption! " + e.getMessage();
		}
		
		return result;
	}

	public static HashMap<String, String> getPDFInfo(File pdf) throws IOException {
		PdfReader reader = new PdfReader(pdf.getAbsolutePath());
		HashMap<String, String> info = reader.getInfo();
		info.put("Pages", String.valueOf(reader.getNumberOfPages()));
		return info;
	}
	
//    @SuppressWarnings("null")
//	public static boolean verifyPDFsignature(String path, X509CertificateHolder holder, X509CertificateHolder root) {
//    	boolean signatureValid = false;
//		try {
//			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//			ks.load(null, null);
//			ks.setCertificateEntry("other", CertificationUtils.getCertificateFromHolder(root));
//			ks.setCertificateEntry("cacert", CertificationUtils.getCertificateFromHolder(holder));
//
//	    	File source = new File(path);
//	        PdfReader reader = new PdfReader(source.getAbsolutePath());
//	        AcroFields af = reader.getAcroFields();
//	        ArrayList<String> names = af.getSignatureNames();
//	        for (String name : names) {
//	            PdfPKCS7 pk = af.verifySignature(name);
//				Calendar cal = pk.getSignDate();
//	            Certificate[] pkc = new Certificate[] {CertificationUtils.getCertificateFromHolder(holder), CertificationUtils.getCertificateFromHolder(root)};
//				Object fails[] = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
//				if (fails != null) {//TODO lol
//					signatureValid = true;
//					System.out.println("Certificates verified against the KeyStore");
//				}
//				else
//					System.out.println("Certificate failed: " + fails[1]);    
//	        }
//	        
//	        return signatureValid;
//
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (KeyStoreException e) {
//			e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		} catch (CertificateException e) {
//			e.printStackTrace();
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//        
//        return signatureValid;
//    }
}
