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
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.util.encoders.Hex
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * This class is responsible for performing the certificate authority (CA) operations for the TLS Toolkit. It delegates
 * much of the internal operations to {@link CertificateUtils} and exposes a simple API. Static methods can be used for
 * both client and server operations, while instance methods are for a specific CA.
 */
class CAService {
    private static final Logger logger = LoggerFactory.getLogger(CAService.class)

    static final String DEFAULT_ALGORITHM = "RSA"
    static final String DEFAULT_SIGNING_ALGORITHM = "SHA256withRSA"
    static final int DEFAULT_KEY_SIZE = 2048
    static final int DEFAULT_CERT_VALIDITY_DAYS = 1095

    boolean isVerbose = false

    private String token
    private KeyPair caKeyPair
    private X509Certificate caCert

    /**
     * Returns an instance of the service that generates a new {@link KeyPair}.
     *
     * @param token the MITM token to use
     */
    CAService(String token, String caDistinguishedName) {
        def keyPair = generateKeyPair()
        CAService(token, keyPair, generateCACertificate(keyPair, caDistinguishedName))
    }

    /**
     * Returns an instance of the service that uses the provided token and {@link KeyPair}.
     *
     * @param token the MITM token to use
     * @param keyPair the CA key pair
     */
    CAService(String token, KeyPair keyPair, X509Certificate signingCertificate) {
        this.token = token
        this.caKeyPair = keyPair
        this.caCert = signingCertificate
    }

    /**
     * Returns an instance of the service that uses the provided token and forms a {@link KeyPair}
     * from the public and private keys. Useful when the keys are loaded externally.
     *
     * @param token the MITM token to use
     * @param publicKey the public key
     * @param privateKey the private key
     */
    CAService(String token, PublicKey publicKey, PrivateKey privateKey, X509Certificate signingCertificate) {
        this(token, new KeyPair(publicKey, privateKey), signingCertificate)
    }

    // TODO: Add parameter guards (callers expected to pass valid data for now)

    /**
     * Returns a {@link KeyPair} containing the public and private key values for the provided algorithm and key size.
     *
     * @param algorithm "RSA" (default), "EC", "DSA", or "DiffieHellman"
     * @param keySize 2048 (default) or higher is recommended
     * @return the key pair
     */
    static KeyPair generateKeyPair(String algorithm = DEFAULT_ALGORITHM, int keySize = DEFAULT_KEY_SIZE) {
        logger.debug("Generating key pair for ${algorithm} with key size ${keySize}")
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm)
        generator.initialize(keySize)
        KeyPair keyPair = generator.generateKeyPair()
        logger.debug("Generated key pair ${keyPair}")
        keyPair
    }

    /**
     * Returns the {@link java.security.cert.X509Certificate} identifying the given DN. The cert has the key usages and EKU set for certificate signing, and is signed by itself.
     *
     * @param keyPair the public and private key to use
     * @param dn the Distinguished Name (hostname, email, etc.)
     * @param signingAlgorithm "SHA256withRSA" (default), "SHA256withECDSA", etc.
     * @param certificateDurationDays the number of days to mark this certificate valid (defaults to 1095 / 3 years)
     * @param sans an optional list of {@code SubjectAlternativeNames} as Strings (default empty)
     * @return the signed certificate
     */
    static X509Certificate generateCACertificate(KeyPair keyPair, String dn, String signingAlgorithm = DEFAULT_SIGNING_ALGORITHM, int certificateDurationDays = DEFAULT_CERT_VALIDITY_DAYS, List<String> sans = []) {
        logger.debug("Generating CA certificate with DN ${dn}, SANS ${sans}, signing algorithm ${signingAlgorithm}, and certificate duration days ${certificateDurationDays}")

        Extensions sanExtensions = null
        if (sans) {
            logger.debug("${sans.size()} SAN entries provided")
            sanExtensions = TlsToolkitUtil.generateSubjectAlternativeNamesExtensions(sans)
        }

        X509Certificate caCert = CertificateUtils.generateSelfSignedX509Certificate(keyPair, dn, sanExtensions, signingAlgorithm, certificateDurationDays)
        logger.debug("Generated CA cert ${caCert.toString()}")
        caCert
    }

    /**
     * Returns the signed {@link X509Certificate}.
     *
     * @param csr the certificate signing request
     * @param providedHmac the hex-encoded HMAC provided by the requester
     * @return the signed certificate
     */
    X509Certificate signCSR(JcaPKCS10CertificationRequest csr, String providedHmac, String signingAlgorithm = DEFAULT_SIGNING_ALGORITHM, int certDaysValid = DEFAULT_CERT_VALIDITY_DAYS) {
        // Verify the HMAC
        logger.info("Verifying provided HMAC ${providedHmac}")
        byte[] expectedHmac = TlsToolkitUtil.calculateHMac(token, csr.getPublicKey())
        if (MessageDigest.isEqual(expectedHmac, Hex.decode(providedHmac))) {
            // The HMAC is valid, sign the certificate
            String dn = csr.getSubject().toString()
            logger.info("Received CSR with DN ${dn} and SPKI ${csr.subjectPublicKeyInfo}")
            X509Certificate issuedCertificate = CertificateUtils.generateIssuedCertificate(dn, csr.getPublicKey(),
                    CertificateUtils.getExtensionsFromCSR(csr), caCert, caKeyPair, signingAlgorithm, certDaysValid)

            logger.info("Issued certificate for DN ${dn} signed by ${caCert.subjectX500Principal.name} valid until ${new Date() + certDaysValid}")
            issuedCertificate
        } else {
            throw new GeneralSecurityException("The provided HMAC was not valid")
        }
    }

    @Override
    String toString() {
        "CA Service for ${caCert.subjectX500Principal.name} with token ${"*" * token.size()}"
    }

    static JcaPKCS10CertificationRequest generateCSR(String dn, List<String> sans, KeyPair keyPair, String signingAlgorithm = CAService.DEFAULT_SIGNING_ALGORITHM) {
        logger.info("Generating CSR for ${dn}")
        JcaPKCS10CertificationRequest csr = TlsToolkitUtil.generateCertificateSigningRequest(dn, sans, keyPair, signingAlgorithm)
        logger.info("Generated CSR for ${csr.subject}")
        csr
    }
}
