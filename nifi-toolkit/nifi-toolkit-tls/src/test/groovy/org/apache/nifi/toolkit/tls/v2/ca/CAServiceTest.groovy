/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.nifi.toolkit.tls.v2.ca

import org.apache.nifi.security.util.CertificateUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate

@RunWith(JUnit4.class)
class CAServiceTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CAServiceTest.class)

    private static final int KEY_SIZE = 2048

    private static final int DAYS_IN_YEAR = 365
    private static final long YESTERDAY = System.currentTimeMillis() - 24 * 60 * 60 * 1000
    private static final long ONE_YEAR_FROM_NOW = System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA"
    private static final String PROVIDER = "BC"

    private static final String SUBJECT_DN = "CN=NiFi Test Server,OU=Security,O=Apache,ST=CA,C=US"
    private static final String ISSUER_DN = "CN=NiFi Test CA,OU=Security,O=Apache,ST=CA,C=US"
    private final int DEFAULT_CERT_AGE_DAYS = 1094

    @BeforeClass
    static void setUpOnce() {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() {
        super.setUp()

    }

    @After
    void tearDown() {

    }

    /**
     * Generates a public/private RSA keypair using the default key size.
     *
     * @return the keypair
     * @throws java.security.NoSuchAlgorithmException if the RSA algorithm is not available
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(KEY_SIZE)
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Generates a signed certificate using an on-demand keypair.
     *
     * @param dn the DN
     * @return the certificate
     */
    private
    static X509Certificate generateCertificate(String dn) {
        KeyPair keyPair = generateKeyPair()
        return CertificateUtils.generateSelfSignedX509Certificate(keyPair, dn, SIGNATURE_ALGORITHM, DAYS_IN_YEAR)
    }

    /**
     * Generates a certificate signed by the issuer key.
     *
     * @param dn the subject DN
     * @param issuerDn the issuer DN
     * @param issuerKey the issuer private key
     * @return the certificate
     */
    private
    static X509Certificate generateIssuedCertificate(String dn, X509Certificate issuer, KeyPair issuerKey) {
        KeyPair keyPair = generateKeyPair()
        return CertificateUtils.generateIssuedCertificate(dn, keyPair.getPublic(), issuer, issuerKey, SIGNATURE_ALGORITHM, DAYS_IN_YEAR)
    }

    /**
     * Normal invocation (caller provides arguments).
     */
    @Test
    void testShouldGenerateCACertificate() {
        // Arrange
        final String CN = "nifi-ca.nifi.apache.org"
        final String DN = "CN=" + CN
        final List<String> SANS = ["127.0.0.1", "nifi.nifi.apache.org"]
        logger.info("Creating a certificate with subject: ${DN} and SAN: ${SANS}")

        // Expected value should also include CN
        final List<String> ALL_SANS = SANS + CN
        logger.info("Expected SANS: ${ALL_SANS}")

        KeyPair keyPair = generateKeyPair()
        def certAgeDays = 5

        // Act
        final X509Certificate caCertificate = CAService.generateCACertificate(keyPair, DN, CAService.DEFAULT_SIGNING_ALGORITHM, certAgeDays, SANS)
        logger.info("Issued certificate with subject: ${caCertificate.getSubjectDN().name} and SAN: ${caCertificate.getSubjectAlternativeNames().join(",")}")

        // Assert
        assert caCertificate instanceof X509Certificate
        assert caCertificate.getSubjectDN().name == DN
        assert caCertificate.getSubjectAlternativeNames().size() == ALL_SANS.size()
        assert caCertificate.getSubjectAlternativeNames()*.last().containsAll(ALL_SANS)

        // Check key pair
        caCertificate.verify(keyPair.public)

        // Would throw exception if invalid
        caCertificate.checkValidity() // now
        caCertificate.checkValidity(new Date() + certAgeDays - 1) // right before expiry

        def msg = shouldFail(CertificateNotYetValidException) {
            caCertificate.checkValidity(new Date() - 1) // right before now
        }
        logger.expected(msg)

        msg = shouldFail(CertificateExpiredException) {
            caCertificate.checkValidity(new Date() + certAgeDays + 1) // right after expiry
        }
        logger.expected(msg)
    }

    /**
     * Default (simplest) invocation.
     */
    @Test
    void testShouldGenerateCACertificateWithDefaults() {
        // Arrange
        final String CN = "nifi-ca.nifi.apache.org"
        final String DN = "CN=" + CN
        logger.info("Creating a certificate with subject: ${DN}")

        KeyPair keyPair = generateKeyPair()

        // Act
        final X509Certificate caCertificate = CAService.generateCACertificate(keyPair, DN)
        logger.info("Issued certificate with subject: ${caCertificate.getSubjectDN().name} and SAN: ${caCertificate.getSubjectAlternativeNames().join(",")}")

        // Assert
        assert caCertificate instanceof X509Certificate
        assert caCertificate.getSubjectDN().name == DN
        assert caCertificate.getSubjectAlternativeNames().size() == 1
        assert caCertificate.getSubjectAlternativeNames()*.last().containsAll([CN])

        // Check key pair
        caCertificate.verify(keyPair.public)

        // Would throw exception if invalid
        caCertificate.checkValidity() // now
        caCertificate.checkValidity(new Date() + DEFAULT_CERT_AGE_DAYS - 1) // right before expiry

        def msg = shouldFail(CertificateNotYetValidException) {
            caCertificate.checkValidity(new Date() - 1) // right before now
        }
        logger.expected(msg)

        msg = shouldFail(CertificateExpiredException) {
            caCertificate.checkValidity(new Date() + DEFAULT_CERT_AGE_DAYS + 1) // right after expiry
        }
        logger.expected(msg)
    }
}
