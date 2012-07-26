package org.megadevs.security.client.utils;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@SuppressWarnings("rawtypes")
public class NetworkUtils {
	
	private static final String URL_SERVER = "http://localhost:8080/Sicurezza-Server/ca/remote/";
	
	public static String prepareXMLMessage(String content) {
		return "<message><content>"+content+"</content></message>";
	}
	
	public static String generateXMLSignature(String xml, KeyPair pair) {
		
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); 
			dbf.setNamespaceAware(true); 

			DocumentBuilder builder = dbf.newDocumentBuilder();

			InputSource in = new InputSource();
			in.setCharacterStream(new StringReader(xml));
			Document doc = builder.parse(in);
			
			DOMSignContext dsc = new DOMSignContext(pair.getPrivate(), doc.getDocumentElement());
			XMLSignatureFactory fac =  XMLSignatureFactory.getInstance("DOM"); 

			Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
					    Collections.singletonList(fac.newTransform(Transform.ENVELOPED,(TransformParameterSpec) null)), null, null); 

			SignedInfo si = fac.newSignedInfo
					  (fac.newCanonicalizationMethod
					    (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
					      (C14NMethodParameterSpec) null),
					    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
					    Collections.singletonList(ref)); 

			KeyInfoFactory kif = fac.getKeyInfoFactory(); 
			KeyValue kv = kif.newKeyValue(pair.getPublic());
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv)); 

			XMLSignature signature = fac.newXMLSignature(si, ki); 
			signature.sign(dsc); 

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(baos)); 

			return baos.toString();
			
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (KeyException e) {
			e.printStackTrace();
		} catch (MarshalException e) {
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			e.printStackTrace();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}  
		
		return null;
	}
	
	public static boolean validateXMLSignature(String signedXML) {
		
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);

			DocumentBuilder builder = dbf.newDocumentBuilder();
			
			InputSource in = new InputSource();
			in.setCharacterStream(new StringReader(signedXML));
			Document doc = builder.parse(in);

			NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (nl.getLength() == 0) {
				throw new Exception("Cannot find Signature element");
			}
			
			DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
			XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			
			boolean coreValidity = signature.validate(valContext);

			return coreValidity;
			
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return false;
	}

	private static class KeyValueKeySelector extends KeySelector {

		public KeySelectorResult select(KeyInfo keyInfo,
				KeySelector.Purpose purpose,
				AlgorithmMethod method,
				XMLCryptoContext context)
						throws KeySelectorException {

			if (keyInfo == null) {
				throw new KeySelectorException("Null KeyInfo object!");
			}
			SignatureMethod sm = (SignatureMethod) method;
			List list = keyInfo.getContent();

			for (int i = 0; i < list.size(); i++) {
				XMLStructure xmlStructure = (XMLStructure) list.get(i);
				if (xmlStructure instanceof KeyValue) {
					PublicKey pk = null;
					try {
						pk = ((KeyValue)xmlStructure).getPublicKey();
					} catch (KeyException ke) {
						throw new KeySelectorException(ke);
					}
					// make sure algorithm is compatible with method
					if (algEquals(sm.getAlgorithm(), 
							pk.getAlgorithm())) {
						return new SimpleKeySelectorResult(pk);
					}
				}
			}
			throw new KeySelectorException("No KeyValue element found!");
		}

		private static boolean algEquals(String algURI, String algName) {
			if (algName.equalsIgnoreCase("DSA") &&
					algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
				return true;
			} else if (algName.equalsIgnoreCase("RSA") &&
					algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
				return true;
			} else {
				return false;
			}
		}
	}
	

	public static String sendMessageToServer(String message, String path) {
			try {
				HttpClient def = new DefaultHttpClient();
				HttpPost post = new HttpPost(URL_SERVER + path);
				
				ArrayList<NameValuePair> pairs = new ArrayList<NameValuePair>();
				pairs.add(new BasicNameValuePair("message", message));
				
				UrlEncodedFormEntity entity = new UrlEncodedFormEntity(pairs, "UTF-8");
				post.setEntity(entity);
				HttpResponse httpResponse;
				System.out.println(post.getURI().toURL().toString());
				httpResponse = def.execute(post);
				HttpEntity responseEntity = httpResponse.getEntity();
				System.out.println(httpResponse.getStatusLine().getStatusCode());
				
				if (httpResponse.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
					String respMessage = convertStreamToString(responseEntity.getContent());
					return respMessage;
				}
			} catch (ClientProtocolException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
        
        return null;
	}
	
	public static String getCharacterDataFromElement(Element e) {
		Node child = e.getFirstChild();
		if (child instanceof CharacterData) {
			CharacterData cd = (CharacterData) child;
			return cd.getData();
		}
		return "?";
	}

	public static String convertStreamToString(InputStream is) {
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		StringBuilder sb = new StringBuilder();

		String line = null;
		try {
			while ((line = reader.readLine()) != null) {
				sb.append(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return sb.toString();
	}
}
