import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

public class CSRSigner {
	
	public static void main(String[] args) throws Throwable {
		if (args != null && args.length == 3) {
			KeyStore ks = KeyStore.getInstance("JKS");
			FileReader reader = new FileReader(args[2]);
			
			ks.load(new FileInputStream(args[0]), args[1].toCharArray());
			System.out.println(signCSR(reader, ks, "skey", args[1].toCharArray(), "p7b"));

		    /*=========================================================================*/
		    String filename = "clientFromCA2.p7b";
		    final FileOutputStream os = new FileOutputStream(filename); 
			 reader = new FileReader(args[2]);
		    os.write(signCSR(reader, ks, "skey", args[1].toCharArray(), "p7b").getBytes());
		    os.close();
		    /*=========================================================================*/
		}
	}
	
	public static String signCSR(Reader pemcsr, KeyStore keystore, String alias, char[] password, String returnPackage) throws Exception {
	    PrivateKey cakey = (PrivateKey)keystore.getKey(alias, password);
	    X509Certificate cacert = (X509Certificate)keystore.getCertificate(alias);
	    PEMParser reader = null;
	    PKCS10CertificationRequest csr;
	    
	    try {
	    	reader = new PEMParser(pemcsr);
		    csr = new PKCS10CertificationRequest(reader.readPemObject().getContent());
	    } finally {
	    	if (reader != null) {
	    		reader.close();
	    	}
	    }

	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
	    X500Name issuer = new X500Name(cacert.getSubjectX500Principal().getName());
	    BigInteger serial = new BigInteger(32, new SecureRandom());
	    Date from = new Date();
	    Date to = new Date(System.currentTimeMillis() + (365 * 86400000L));
	    
	    DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
	    X509ExtensionUtils extUtils = new X509ExtensionUtils(digCalc);

	    X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject(), csr.getSubjectPublicKeyInfo());
	    certgen.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
	    certgen.addExtension(X509Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
	    certgen.addExtension(X509Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(cacert.getPublicKey().getEncoded()))));

	    ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(cakey.getEncoded()));
	    X509CertificateHolder holder = certgen.build(signer);
	    byte[] certencoded = holder.toASN1Structure().getEncoded();

	    
	    ByteArrayOutputStream out = new ByteArrayOutputStream();
	    if (returnPackage != null && "cer".equalsIgnoreCase(returnPackage)) {
		    out.write("-----BEGIN CERTIFICATE-----\n".getBytes("ISO-8859-1"));
		    out.write(Base64.encode(certencoded));
		    out.write("\n-----END CERTIFICATE-----\n".getBytes("ISO-8859-1"));
	    } else {
		    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		    signer = new JcaContentSignerBuilder("SHA1withRSA").build(cakey);
		    generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, cacert));
		    generator.addCertificate(new X509CertificateHolder(certencoded));
		    generator.addCertificate(new X509CertificateHolder(cacert.getEncoded()));
		    CMSTypedData content = new CMSProcessableByteArray(certencoded);
		    CMSSignedData signeddata = generator.generate(content, true);

		    out.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
		    out.write(Base64.encode(signeddata.getEncoded()));
		    out.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
		    
		    DEROutputStream dos = new DEROutputStream(new FileOutputStream("clientFromCA.p7b"));
		    dos.writeObject(signeddata.toASN1Structure());
		    dos.close();
	    }
	    out.close();
	    return new String(out.toByteArray(), "ISO-8859-1");
	}
	
}
