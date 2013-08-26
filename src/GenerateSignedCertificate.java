
import java.security.*;
import java.io.*;
import java.util.Date;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.openssl.*;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.crypto.util.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemWriter;


public class GenerateSignedCertificate {
	static String Path = "E:/Projects/BouncyCastleSample/res/"; 
	  private static EncodedKeySpec generateSpec(String filename,boolean isPublic) throws Exception
	  {

	  	File f = new File(filename);
	  	FileInputStream fis = new FileInputStream(f);
	  	DataInputStream dis = new DataInputStream(fis);
	  	byte[] keyBytes = new byte[(int)f.length()];
	  	dis.readFully(keyBytes);
	  	dis.close();
	  	if(isPublic)
	  		return new X509EncodedKeySpec(keyBytes);
	  	else
	  		return new PKCS8EncodedKeySpec(keyBytes);
	  }
	  private KeyPair readPublicAndPrivateKey() throws Exception
	  {
	  	KeyFactory kf = KeyFactory.getInstance("RSA");
	  	PrivateKey privateKey =  kf.generatePrivate(generateSpec(Path+"private_key.der",false));
	  	PublicKey publicKey =  kf.generatePublic(generateSpec(Path+"public_key.der",true));
	  	KeyPair keyPair = new KeyPair(publicKey,privateKey);
	  	return keyPair;
	  }
	  private X509Certificate readCertificate() throws Exception {
	 	 FileInputStream fis = null;
	 	 ByteArrayInputStream bais = null;
	 	  // use FileInputStream to read the file
	 	  fis = new FileInputStream(Path+"CRootCA.der");
	 	  
	 	  // read the bytes
	 	  byte value[] = new byte[fis.available()];
	 	  fis.read(value);
	 	  fis.close();
	 	  bais = new ByteArrayInputStream(value);
	 	  
	 	  // get X509 certificate factory
	 	  CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	 	   
	 	  // certificate factory can now create the certificate 
	 	  return (X509Certificate)certFactory.generateCertificate(bais);
	 }
	/**
	 * Given a Keystore containing a private key and certificate and a Reader containing a PEM-encoded
	 * Certificiate Signing Request (CSR), sign the CSR with that private key and return the signed
	 * certificate as a PEM-encoded PKCS#7 signedData object. The returned value can be written to a file
	 * and imported into a Java KeyStore with "keytool -import -trustcacerts -alias subjectalias -file file.pem"
	 *
	 * @param pemcsr a Reader from which will be read a PEM-encoded CSR (begins "-----BEGIN NEW CERTIFICATE REQUEST-----")
	 * @param validity the number of days to sign the Certificate for
	 * @param keystore the KeyStore containing the CA signing key
	 * @param alias the alias of the CA signing key in the KeyStore
	 * @param password the password of the CA signing key in the KeyStore
	 *
	 * @return a String containing the PEM-encoded signed Certificate (begins "-----BEGIN PKCS #7 SIGNED DATA-----")
	 */
	public void signCSR(Reader pemcsr, int validity, KeyStore keystore, String alias, char[] password) throws Exception {
		KeyPair keyPair = readPublicAndPrivateKey();
	    PrivateKey cakey = keyPair.getPrivate();
	    X509Certificate cacert = (X509Certificate)readCertificate();
//	    PrivateKey cakey = (PrivateKey)keystore.getKey(alias, password);
//	    X509Certificate cacert = (X509Certificate)keystore.getCertificate(alias);
	    PEMReader reader = new PEMReader(pemcsr);
	    PKCS10CertificationRequest csr = new PKCS10CertificationRequest((CertificationRequest)reader.readObject());

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
	    X500Name issuer = new X500Name(cacert.getSubjectX500Principal().getName());
	    BigInteger serial = new BigInteger(32, new SecureRandom());
	    Date from = new Date();
	    Date to = new Date(System.currentTimeMillis() + (validity * 86400000L));

	    X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject(), csr.getSubjectPublicKeyInfo());
	    certgen.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
	    certgen.addExtension(X509Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
	    certgen.addExtension(X509Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(new X509Name(cacert.getSubjectX500Principal().getName()))), cacert.getSerialNumber()));

	    ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(cakey.getEncoded()));
	    X509CertificateHolder holder = certgen.build(signer);
	    byte[] certencoded = holder.toASN1Structure().getEncoded();

	    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
	    signer = new JcaContentSignerBuilder("SHA1withRSA").build(cakey);
	    generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cacert));
	    generator.addCertificate(new X509CertificateHolder(certencoded));
	    generator.addCertificate(new X509CertificateHolder(cacert.getEncoded()));
	    CMSTypedData content = new CMSProcessableByteArray(certencoded);
	    CMSSignedData signeddata = generator.generate(content, true);

	    ByteArrayOutputStream out = new ByteArrayOutputStream();
//	    out.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
//	    out.write(Base64.encode(signeddata.getEncoded()));
//	    out.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
//	    out.close();

		  String filename = Path+"clientFromCA4.der";
	  	final FileOutputStream os = new FileOutputStream(filename);  
	   // PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
	    PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(os));

	    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate cert = null;
        cert = converter.getCertificate(holder);
	    pemWrt.writeObject(cert);
	    pemWrt.writeObject(cacert);

	    pemWrt.close();  
	    
	}
	private static void main2() throws Exception
	{
		FileReader fileReader = new FileReader(Path+"client.csr");
		int valid_days = 1;		
		GenerateSignedCertificate gsc = new GenerateSignedCertificate();
		gsc.signCSR(fileReader, valid_days, null, null, null);
		
	}
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		GenerateSignedCertificate.main2();
	}

}