package org.sci;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
//import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

//import com.google.api.client.util.Base64;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.SecurityUtils;




public class PfxSigner
{
	private static final String KEYSTORE_PASSWORD = "Rudra@2601";
    private static final String SIGNATUREALGO = "SHA1withRSA";
    private static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----";
public static void main(String[] args) throws Exception
{
	String contentPk = new String(Files.readAllBytes(Paths.get("C:\\Users\\db2admin\\Downloads\\AUCB_PFMS.key")));
	KeyStore keystore=SecurityUtils.getPkcs12KeyStore();
	SecurityUtils.loadKeyStore(keystore,  new FileInputStream(new File("C:\\Users\\db2admin\\Downloads\\Sanjay Srivastava Encryption.pfx")), "Rudra@2601");
	String aliasname=keystore.aliases().nextElement(); 
	PrivateKey key=PfxSigner.getPrivateKey();
	System.out.println("*********"+key);
	
	PrivateKey key2=PfxSigner.getPrivateKeyFrmFile(contentPk);
	System.out.println("Private Key from file is"+key2);
	
	Signature signature=Signature.getInstance("SHA1withRSA");
	signature.initSign(key);
	System.out.println("***************************************************************************************");
	System.out.println("Signing using PKCS#7 Format.....");
	CMSSignedDataGenerator signatureGenerator = PfxSigner.setUpProvider(keystore);
	byte[] content1 =PfxSigner.getAllBytes(new File("F:\\ssd\\MMS-CREATE-UTKS-UTKS17505-08092020-000263-INP"));
//	System.out.println("****************************************************************************************");
	/*
	  String contentsData=Base64.encodeBase64String(content1);
	 
	System.out.println("content is"+contentsData);
	byte[] signedBytes=PfxSigner.signPkcs7(content1, signatureGenerator);
	System.out.println("PKCS#7 style of Signing"+signedBytes);
	String str2=Base64.encodeBase64String(signedBytes);
	System.out.println("1.=========================================================================================");
	System.out.println(str2);
	System.out.println("2.=========================================================================================");
	System.out.println(contentsData);
	System.out.println("===========================================================================================");	
	byte[] fileContent = Files.readAllBytes(Paths.get("C:\\Users\\db2admin\\Downloads\\Sanjay Srivastava Encryption.pfx"));
	String base64Cert=Base64.encodeBase64String(fileContent);
	System.out.println("3.===========================================================================================");
	System.out.println(base64Cert);
	System.out.println("===========================================================================================");
	String result=PfxSigner.getXmlInfo(contentsData,str2,base64Cert);
	System.out.println("==========================================================================================");
	System.out.println(result);
	*/
}

public static byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws Exception {

    CMSTypedData cmsdata = new CMSProcessableByteArray(content);
    CMSSignedData signeddata = generator.generate(cmsdata, true);
    return signeddata.getEncoded();
}

/*
 * Generating Private Key
 */

public static PrivateKey  getPrivateKey() throws FileNotFoundException, IOException, GeneralSecurityException
{
	KeyStore keystore=SecurityUtils.getPkcs12KeyStore();
	SecurityUtils.loadKeyStore(keystore,  new FileInputStream(new File("C:\\Users\\db2admin\\Downloads\\Sanjay Srivastava Encryption.pfx")), "Rudra@2601");
	String aliasname=keystore.aliases().nextElement(); 
	System.out.println("***********"+aliasname);
	PrivateKey privateKey = SecurityUtils.getPrivateKey(keystore, aliasname,"Rudra@2601");

	return privateKey;
	 
}

/*
 * CMSSignedDatagenerator
 */
public static CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {

	KeyStore keystore1=SecurityUtils.getPkcs12KeyStore();
	SecurityUtils.loadKeyStore(keystore1,  new FileInputStream(new File("C:\\Users\\db2admin\\Downloads\\Sanjay Srivastava Encryption.pfx")), "Rudra@2601");
	String aliasname=keystore1.aliases().nextElement(); 
	System.out.println("***********"+aliasname);
    Security.addProvider(new BouncyCastleProvider());

    Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(aliasname);

    final List<Certificate> certlist = new ArrayList<Certificate>();

    for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
        certlist.add(certchain[i]);
    }

    Store certstore = new JcaCertStore(certlist);

    Certificate cert = keystore.getCertificate(aliasname);

    ContentSigner signer = new JcaContentSignerBuilder(SIGNATUREALGO).setProvider("BC").
            build((PrivateKey) (keystore.getKey(aliasname, KEYSTORE_PASSWORD.toCharArray())));

    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

    generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
            build()).build(signer, (X509Certificate) cert));

    generator.addCertificates(certstore);

    return generator;
}
/*
 * Folder contents 
 */
public static byte[] getAllBytes(File folderName) throws IOException
{
	String[] sourceFiles=null;
	if(folderName.isDirectory())
	{
		 sourceFiles =folderName.list();
	}

	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	ZipOutputStream zout = new ZipOutputStream(baos);

	byte[] buffer = new byte[4096];

	for (int i = 0; i < sourceFiles.length; i++)
	{
	    FileInputStream fin = new FileInputStream("F:\\ssd\\MMS-CREATE-UTKS-UTKS17505-08092020-000263-INP\\"+sourceFiles[i]);
	    zout.putNextEntry(new ZipEntry(sourceFiles[i]));

	    int length;
	    while ((length = fin.read(buffer)) > 0)
	    {
	        zout.write(buffer, 0, length);
	    }

	    zout.closeEntry();
	    fin.close();
	}

	zout.close();

	byte[] bytes = baos.toByteArray();
	return bytes;
}

public static String getXmlInfo(String x1,String x2,String x3)
{
	// ---- Preparing XML of the signed file ----
	String xmlFileSigned;
	xmlFileSigned = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\n<Envelope>\n\t<OrgContent>"
	+ x1+ "</OrgContent>\n\t<Signature>" + x2
	+ "</Signature>\n\t<Certificate>" + x3 + "</Certificate>\n</Envelope>";
	try {
	      FileWriter myWriter = new FileWriter("F:\\ssd\\filename.txt");
	      myWriter.write(xmlFileSigned);
	      myWriter.close();
	      System.out.println("Successfully wrote to the file.");
	    } catch (IOException e) {
	      System.out.println("An error occurred.");
	      e.printStackTrace();
	    }
	return xmlFileSigned;
}
public static PrivateKey getPrivateKeyFrmFile(String contents) 
{
	String privKeyPEM = contents.replace(
			"-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "")
			 .replaceAll(System.lineSeparator(), "")
			    .replace("-----END ENCRYPTED PRIVATE KEY-----", "");

			// Base64 decode the data

			byte[] encodedPrivateKey = Base64.decode(privKeyPEM);
			PrivateKey pk=null;
			try {
			    ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
			        .fromByteArray(encodedPrivateKey);
			    Enumeration<?> e = primitive.getObjects();
			    BigInteger v = ((DERInteger) e.nextElement()).getValue();

			    int version = v.intValue();
			    if (version != 0 && version != 1) {
			        throw new IllegalArgumentException("wrong version for RSA private key");
			    }
			    /**
			     * In fact only modulus and private exponent are in use.
			     */
			    BigInteger modulus = ((DERInteger) e.nextElement()).getValue();
			    BigInteger publicExponent = ((DERInteger) e.nextElement()).getValue();
			    BigInteger privateExponent = ((DERInteger) e.nextElement()).getValue();
			    BigInteger prime1 = ((DERInteger) e.nextElement()).getValue();
			    BigInteger prime2 = ((DERInteger) e.nextElement()).getValue();
			    BigInteger exponent1 = ((DERInteger) e.nextElement()).getValue();
			    BigInteger exponent2 = ((DERInteger) e.nextElement()).getValue();
			    BigInteger coefficient = ((DERInteger) e.nextElement()).getValue();

			    RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			     pk = kf.generatePrivate(spec);
			} catch (IOException e2) {
			    throw new IllegalStateException();
			} catch (NoSuchAlgorithmException e) {
			    throw new IllegalStateException(e);
			} catch (InvalidKeySpecException e) {
			    throw new IllegalStateException(e);
			}
			return pk;
}


}