package org.megadevs.security.client.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CertificationUtils {

	public static KeyUsage getKeyUsageFromRequest(PKCS10CertificationRequest request) {
		try {
			Vector<ASN1ObjectIdentifier> oidSS = new Vector<ASN1ObjectIdentifier>();
			Vector<Extension> values = new Vector<Extension>();

			Attribute[] list = request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
			if (list.length >= 1) {
				Extensions ext = Extensions.getInstance(list[0].getAttrValues().getObjectAt(0));
				ASN1ObjectIdentifier[] obid = ext.getExtensionOIDs();
				for (int i=0; i<obid.length; i++) {
					oidSS.add(obid[i]);
					values.add(ext.getExtension(obid[i]));
				}
			}

			ASN1InputStream is = new ASN1InputStream(values.get(0).getExtnValue().getOctetStream());
			KeyUsage keyusage;
			keyusage = new KeyUsage((DERBitString) is.readObject());
			return keyusage;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static X509Certificate getCertificateFromHolder(X509CertificateHolder holder) {
		try {
			ByteArrayInputStream in = new ByteArrayInputStream(holder.getEncoded());
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(in); 
			return certificate;
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}

		return null;
	}
	
}
