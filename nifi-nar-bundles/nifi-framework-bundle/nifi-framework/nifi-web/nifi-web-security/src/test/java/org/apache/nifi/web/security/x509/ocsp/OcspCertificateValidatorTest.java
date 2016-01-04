package org.apache.nifi.web.security.x509.ocsp;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

public class OcspCertificateValidatorTest {
    private static final Logger logger = LoggerFactory.getLogger(OcspCertificateValidatorTest.class);

    private static final int KEY_SIZE = 2048;

    private static final long YESTERDAY = System.currentTimeMillis() - 24 * 60 * 60 * 1000;
    private static final long ONE_YEAR_FROM_NOW = System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String PROVIDER = "BC";

    private static final String ISSUER_DN = "CN=NiFi Test CA,OU=Security,O=Apache,ST=CA,C=US";

    private static X509Certificate ISSUER_CERTIFICATE;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

//        ISSUER_CERTIFICATE = generateCertificate(ISSUER_DN);
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {

    }

    /**
     * Generates a public/private RSA keypair using the default key size.
     *
     * @return the keypair
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates a signed certificate using an on-demand keypair.
     *
     * @param dn the DN
     * @return the certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     */
    private static X509Certificate generateCertificate(String dn) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        KeyPair keyPair = generateKeyPair();
        return generateCertificate(dn, keyPair);
    }

    /**
     * Generates a signed certificate with a specific keypair.
     *
     * @param dn      the DN
     * @param keyPair the public key will be included in the certificate and the the private key is used to sign the certificate
     * @return the certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     */
    private static X509Certificate generateCertificate(String dn, KeyPair keyPair) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        PrivateKey privateKey = keyPair.getPrivate();
        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(privateKey);
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        Date startDate = new Date(YESTERDAY);
        Date endDate = new Date(ONE_YEAR_FROM_NOW);

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(dn),
                BigInteger.valueOf(System.currentTimeMillis()),
                startDate, endDate,
                new X500Name(dn),
                subPubKeyInfo);

        // Set certificate extensions
        // (1) digitalSignature extension
        certBuilder.addExtension(X509Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));

        // (2) extendedKeyUsage extension
        Vector<KeyPurposeId> ekUsages = new Vector<>();
        ekUsages.add(KeyPurposeId.id_kp_clientAuth);
        ekUsages.add(KeyPurposeId.id_kp_serverAuth);
        certBuilder.addExtension(X509Extension.extendedKeyUsage, false, new ExtendedKeyUsage(ekUsages));

        // Sign the certificate
        X509CertificateHolder certificateHolder = certBuilder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(certificateHolder);
    }

    /**
     * Generates a certificate signed by the issuer key.
     *
     * @param dn        the subject DN
     * @param issuerDn  the issuer DN
     * @param issuerKey the issuer private key
     * @return the certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     */
    private static X509Certificate generateIssuedCertificate(String dn, String issuerDn, PrivateKey issuerKey) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        KeyPair keyPair = generateKeyPair();
        return generateIssuedCertificate(dn, keyPair.getPublic(), issuerDn, issuerKey);
    }

    /**
     * Generates a certificate with a specific public key signed by the issuer key.
     *
     * @param dn        the subject DN
     * @param publicKey the subject public key
     * @param issuerDn  the issuer DN
     * @param issuerKey the issuer private key
     * @return the certificate
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     */
    private static X509Certificate generateIssuedCertificate(String dn, PublicKey publicKey, String issuerDn, PrivateKey issuerKey) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        ContentSigner sigGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(issuerKey);
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        Date startDate = new Date(YESTERDAY);
        Date endDate = new Date(ONE_YEAR_FROM_NOW);

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
                new X500Name(issuerDn),
                BigInteger.valueOf(System.currentTimeMillis()),
                startDate, endDate,
                new X500Name(dn),
                subPubKeyInfo);

        X509CertificateHolder certificateHolder = v3CertGen.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(certificateHolder);
    }

    private static OCSPResp generateFailedOCSPResponse(OCSPReq request) {
        return null;
    }

//    private static OCSPResp generateSuccessfulOCSPResponse(OCSPReq request) {
//
//        int response = OCSPRespBuilder.INTERNAL_ERROR; // by default response as ERROR
//
//        SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded());
//        BasicOCSPRespBuilder respGen;
//        try {
//            respGen = new BasicOCSPRespBuilder(keyinfo, new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1)); //Create builder
//        } catch (Exception e) {
//            return null;
//        }
//
//        Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
//        if (ext != null) {
//            respGen.setResponseExtensions(new Extensions(new Extension[]{ext})); // Put the nonce back in the response
//        }
//        Req[] requests = request.getRequestList();
//
//        for (int i = 0; i != requests.length; i++) { //For all the Req in the Request
//
//            CertificateID certID = requests[i].getCertID();
//            BigInteger serial = certID.getSerialNumber();
//
//            if (CRLManager.serialNotInCRL(crl, serial)) { // If the certificate is not in the CRL
//                respGen.addResponse(certID, CertificateStatus.GOOD); // Set the status to good
//            } else {
//                respGen.addResponse(certID, new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn)); //Set status privilegeWithdrawn for the given ID
//            }
//        }
//
//        try {
//            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
//            BasicOCSPResp basicResp = respGen.build(contentSigner, new X509CertificateHolder[]{new X509CertificateHolder(caCert.getEncoded())}, new Date());
//            response = OCSPRespBuilder.SUCCESSFUL; //Set response as successful
//            return new OCSPRespBuilder().build(response, basicResp); // build the response
//        } catch (Exception e) {
//            return null;
//        }
//    }

    @Test
    public void testShouldGenerateCertificate() throws Exception {
        // Arrange
        final String testDn = "CN=This is a test";

        // Act
        X509Certificate certificate = generateCertificate(testDn);
        logger.info("Generated certificate: \n{}", certificate);

        // Assert
        assert certificate.getSubjectDN().getName().equals(testDn);
        assert certificate.getIssuerDN().getName().equals(testDn);
        certificate.verify(certificate.getPublicKey());
    }

    @Test
    public void testShouldGenerateCertificateFromKeyPair() throws Exception {
        // Arrange
        final String testDn = "CN=This is a test";
        final KeyPair keyPair = generateKeyPair();

        // Act
        X509Certificate certificate = generateCertificate(testDn, keyPair);
        logger.info("Generated certificate: \n{}", certificate);

        // Assert
        assert certificate.getPublicKey().equals(keyPair.getPublic());
        assert certificate.getSubjectDN().getName().equals(testDn);
        assert certificate.getIssuerDN().getName().equals(testDn);
        certificate.verify(certificate.getPublicKey());
    }

    @Test
    public void testShouldGenerateIssuedCertificate() throws Exception {
        // Arrange
        final String testDn = "CN=This is a signed test";
        final String issuerDn = "CN=Issuer CA";
        final KeyPair issuerKeyPair = generateKeyPair();
        final PrivateKey issuerPrivateKey = issuerKeyPair.getPrivate();

        final X509Certificate issuerCertificate = generateCertificate(issuerDn, issuerKeyPair);
        logger.info("Generated issuer certificate: \n{}", issuerCertificate);

        // Act
        X509Certificate certificate = generateIssuedCertificate(testDn, issuerDn, issuerPrivateKey);
        logger.info("Generated signed certificate: \n{}", certificate);

        // Assert
        assert issuerCertificate.getPublicKey().equals(issuerKeyPair.getPublic());
        assert certificate.getSubjectX500Principal().getName().equals(testDn);
        assert certificate.getIssuerX500Principal().getName().equals(issuerDn);
        certificate.verify(issuerCertificate.getPublicKey());

        try {
            certificate.verify(certificate.getPublicKey());
            Assert.fail("Should have thrown exception");
        } catch (Exception e) {
            assert e instanceof SignatureException;
            assert e.getMessage().contains("certificate does not verify with supplied key");
        }
    }

    @Test
    public void testShouldValidateCertificate() throws Exception {

    }

    @Test
    public void testShouldNotValidateEmptyCertificate() throws Exception {

    }

    @Test
    public void testShouldNotValidateInvalidCertificate() throws Exception {

    }

    @Test
    public void testValidateShouldHandleUnsignedResponse() throws Exception {

    }

    @Test
    public void testValidateShouldHandleResponseWithIncorrectNonce() throws Exception {

    }
}