package org.apache.nifi.web.security.x509.ocsp
import com.sun.jersey.api.client.ClientResponse
import com.sun.jersey.spi.MessageBodyWorkers
import org.apache.nifi.util.NiFiProperties
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

import static groovy.test.GroovyAssert.shouldFail
import static org.junit.Assert.fail

public class OcspCertificateValidatorGroovyTest {
    private static final Logger logger = LoggerFactory.getLogger(OcspCertificateValidatorGroovyTest.class);

    private static final int KEY_SIZE = 2048;

    private static final long YESTERDAY = System.currentTimeMillis() - 24 * 60 * 60 * 1000;
    private static final long ONE_YEAR_FROM_NOW = System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String PROVIDER = "BC";

    private static final String SUBJECT_DN = "CN=NiFi Test Server,OU=Security,O=Apache,ST=CA,C=US";
    private static final String ISSUER_DN = "CN=NiFi Test CA,OU=Security,O=Apache,ST=CA,C=US";

    private NiFiProperties mockProperties

    // System under test
    OcspCertificateValidator certificateValidator

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws Exception {
        mockProperties = [getProperty: { String propertyName -> return "value_for_${propertyName}" }] as NiFiProperties
    }

    @After
    public void tearDown() throws Exception {
        certificateValidator?.metaClass = null
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
    private
    static X509Certificate generateCertificate(String dn) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        KeyPair keyPair = generateKeyPair();
        return generateCertificate(dn, keyPair);
    }

    /**
     * Generates a signed certificate with a specific keypair.
     *
     * @param dn the DN
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
    private
    static X509Certificate generateCertificate(String dn, KeyPair keyPair) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
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
     * @param dn the subject DN
     * @param issuerDn the issuer DN
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
    private
    static X509Certificate generateIssuedCertificate(String dn, String issuerDn, PrivateKey issuerKey) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
        KeyPair keyPair = generateKeyPair();
        return generateIssuedCertificate(dn, keyPair.getPublic(), issuerDn, issuerKey);
    }

    /**
     * Generates a certificate with a specific public key signed by the issuer key.
     *
     * @param dn the subject DN
     * @param publicKey the subject public key
     * @param issuerDn the issuer DN
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
    private
    static X509Certificate generateIssuedCertificate(String dn, PublicKey publicKey, String issuerDn, PrivateKey issuerKey) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException {
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

    private static X509Certificate[] generateCertificateChain(String dn = SUBJECT_DN, String issuerDn = ISSUER_DN) {
        final KeyPair issuerKeyPair = generateKeyPair();
        final PrivateKey issuerPrivateKey = issuerKeyPair.getPrivate();

        final X509Certificate issuerCertificate = generateCertificate(issuerDn, issuerKeyPair);
        final X509Certificate certificate = generateIssuedCertificate(dn, issuerDn, issuerPrivateKey);
        [certificate, issuerCertificate] as X509Certificate[]
    }

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
            fail("Should have thrown exception");
        } catch (Exception e) {
            assert e instanceof SignatureException;
            assert e.getMessage().contains("certificate does not verify with supplied key");
        }
    }

    @Test
    public void testShouldValidateCertificate() throws Exception {
        // Arrange
        KeyPair ocspResponderKeyPair = generateKeyPair();

        X509Certificate[] certificateChain = generateCertificateChain();
        X509CertificateHolder[] certificateHolderChain = certificateChain.collect {
            new X509CertificateHolder(it.encoded)
        }

        // Prepare the successful OCSP response
        // TODO: May not be necessary if the OCSPResp object can just be mangled

//        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM);
//        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
//
//        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(ocspResponderKeyPair.private)
//
//        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(AlgorithmIdentifier.getInstance(digAlgId))
//        CertificateID certId = new CertificateID(digestCalculator, certificateHolderChain[1], certificateChain[0].serialNumber)
//        BasicOCSPResp response = new BasicOCSPRespBuilder(new RespID(new X500Name("CN=OCSP Responder"))).addResponse(certId, CertificateStatus.GOOD).build(contentSigner, certificateHolderChain, new Date());
//        final OCSPResp SUCCESSFUL_RESPONSE = new OCSPResp(response.encoded)


        certificateValidator = new OcspCertificateValidator(mockProperties)

        // Override the validator client with a mock implementation
//        WebResource mockResource = [
//                header: { String name, Object value -> new WebResource().header(name, value) },
//                post  : { Class responseClass, byte[] encoded -> responseClass.newInstance() }
//        ] as MockWebResource
//        Client mockClient = [resource: { URI uri -> mockResource }] as Client
//        certificateValidator.client = mockClient

        certificateValidator.metaClass.getClientResponse = { OCSPReq request ->
            new ClientResponse(ClientResponse.Status.OK, null, new ByteArrayInputStream("Success".bytes), [:] as MessageBodyWorkers)
        }

//        certificateValidator.metaClass.getClientResponse = { OCSPReq request ->
//            new ClientResponse(ClientResponse.Status.OK, null, new ByteArrayInputStream(SUCCESSFUL_RESPONSE.encoded), [:] as MessageBodyWorkers)
//        }

        // Act
        certificateValidator.validate(certificateChain)

        // Assert
        assert true
    }

    @Ignore("To be implemented with Groovy test")
    @Test
    public void testShouldNotValidateEmptyCertificate() throws Exception {

    }

    @Test
    public void testShouldNotValidateRevokedCertificate() throws Exception {
        // Arrange
        X509Certificate[] certificateChain = generateCertificateChain();
        X509CertificateHolder[] certificateHolderChain = certificateChain.collect {
            new X509CertificateHolder(it.encoded)
        }

        certificateValidator = new OcspCertificateValidator(mockProperties)

        certificateValidator.metaClass.getClientResponse = { OCSPReq request ->
            new ClientResponse(ClientResponse.Status.OK, null, new ByteArrayInputStream("Failure".bytes), [:] as MessageBodyWorkers)
        }

        // Act
        def msg = shouldFail(CertificateStatusException) {
            certificateValidator.validate(certificateChain)
        }

        // Assert
        assert msg =~ "is revoked according to the certificate authority"
    }

    @Ignore("To be implemented with Groovy test")
    @Test
    public void testValidateShouldHandleUnsignedResponse() throws Exception {

    }

    @Ignore("To be implemented with Groovy test")
    @Test
    public void testValidateShouldHandleResponseWithIncorrectNonce() throws Exception {

    }
}