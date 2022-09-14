

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;


import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.util.Store;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import static java.lang.System.exit;

import java.io.*;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;


public class KeyStoreTest

{
    private static final long ONE_DAY_IN_MILLIS = 24 * 60 * 60 * 1000;
    private static final long TEN_YEARS_IN_MILLIS = 10l * 365 * ONE_DAY_IN_MILLIS;

    private static Map algIds = new HashMap();

    static
    {
        algIds.put("SHA512WITHSPHINCS256", new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256_with_SHA512));
        algIds.put("SHA256WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers.xmss_mt_SHA256ph));
        algIds.put("SHA512WITHXMSSMT", new AlgorithmIdentifier(BCObjectIdentifiers.xmss_mt_SHA512ph));
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public static void testPKCS12()
            throws Exception
    {
        tryKeyStore("PKCS12");
        //tryKeyStore("PKCS12-DEF");
    }








    public static String x509CertificateToPem(final X509Certificate cert) throws IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }
    private static void tryKeyStore(String format)
            throws Exception
    {
        // Keystore to store certificates and private keys
        KeyStore store = KeyStore.getInstance(format, "BC");

        store.load(null, null);

        String password = "qwertz";
        // XMSS
        X500NameBuilder nameBuilder = new X500NameBuilder();

        nameBuilder.addRDN(BCStyle.CN, "Root CA");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");

        kpg.initialize(new XMSSMTParameterSpec(20, 10, XMSSMTParameterSpec.SHA256), new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        // root CA
        X509Certificate rootCA = createPQSelfSignedCert(nameBuilder.build(), "SHA256WITHXMSSMT", kp);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = rootCA;
        // store root private key
        String alias1 = "xmssmt private";
        store.setKeyEntry(alias1, kp.getPrivate(), password.toCharArray(), chain);
        // store root certificate
        store.setCertificateEntry("root ca", rootCA);



        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.encipherOnly));



        X509Certificate[] chain1 = new X509Certificate[2];
        chain1[1] = rootCA;


        // SPHINCS-256
        kpg = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

        kpg.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256));

        KeyPair sphincsKp = kpg.generateKeyPair();

        extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        X509Certificate cert2 = createCert(nameBuilder.build(), sphincsKp.getPrivate(), new X500Name("CN=sphincs256"), "SHA512WITHSPHINCS256",
                extGenerator.generate(), sphincsKp.getPublic());

        X509Certificate[] chain2 = new X509Certificate[2];
        chain2[1] = rootCA;
        chain2[0] = cert2;




        FileWriter myWriter = new FileWriter("filename.txt");
        myWriter.write(x509CertificateToPem(cert2));
        myWriter.close();

        String text = "This is a message";

        //Sign

        PrivateKey privKey = (PrivateKey) sphincsKp.getPrivate();
        Signature signature = Signature.getInstance("SHA512WITHSPHINCS256", "BCPQC");
        signature.initSign(privKey);
        signature.update(text.getBytes());

        byte [] crack = signature.sign();

        //Build CMS
        X509Certificate cert = (X509Certificate) cert2;
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray(crack);
        certList.add(cert);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA512WITHSPHINCS256").setProvider("BCPQC").build(privKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
        gen.addCertificates(certs);

        CMSSignedData sigData = gen.generate(msg, false);
        ContentInfo ci = ContentInfo.getInstance(ASN1Sequence.fromByteArray(sigData.getEncoded()));
        JcaPEMWriter writer = new JcaPEMWriter(new FileWriter("output.pem"));
        writer.writeObject(ci);
        writer.close();




    }

    private static X509Certificate createPQSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
            throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        long time = System.currentTimeMillis();
        AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());
        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + TEN_YEARS_IN_MILLIS)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        ExtensionsGenerator extGenerator = new ExtensionsGenerator();
        extGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

        certGen.setExtensions(extGenerator.generate());

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);
        sig.initSign(keyPair.getPrivate());
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
                .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, String sigName,
                                              Extensions extensions, PublicKey pubKey)
            throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();
        AtomicLong serialNumber = new AtomicLong(System.currentTimeMillis());

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(signerName);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + TEN_YEARS_IN_MILLIS)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));

        certGen.setExtensions(extensions);

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, BouncyCastlePQCProvider.PROVIDER_NAME);
        sig.initSign(signerKey);
        sig.update(tbsCert.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }


    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        try {
            testPKCS12();
        }
        catch(Exception exception){
            System.out.println("error");
            exit (3);
        }


    }
}