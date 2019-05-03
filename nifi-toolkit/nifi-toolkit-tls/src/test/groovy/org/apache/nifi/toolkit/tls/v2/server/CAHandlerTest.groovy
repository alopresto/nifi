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

package org.apache.nifi.toolkit.tls.v2.server

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.apache.nifi.toolkit.tls.v2.ca.CAService
import util.TlsToolkitUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.Response
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@RunWith(JUnit4.class)
class CAHandlerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CAHandlerTest.class)

    private static final int KEY_SIZE = 2048
    private static final String CA_CN = "nifi-ca.nifi.apache.org"

    private static final String TOKEN = "token" * 4

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

    CAService mockCAService() {
        // Hard to mock because of static methods
//        [:] as CAService
        new CAService(TOKEN, "DN=${CA_CN}")
    }

    // TODO: Currently the entire positive/negative flow is covered, but each component method should be exercised with edge cases

    /**
     * Provide CSR object and inject CA service
     */
    @Test
    void testShouldHandleCSR() {
        // Arrange
        final String CA_CN = "nifi-ca.nifi.apache.org"
        final String CA_DN = "CN=" + CA_CN

        KeyPair caKeyPair = generateKeyPair()

        // Generate the CA
        X509Certificate caCert = CAService.generateCACertificate(caKeyPair, CA_DN)
        logger.info("Issued CA certificate with subject: ${caCert.getSubjectDN().name} and SAN: ${caCert.getSubjectAlternativeNames().join(",")}")

        final String TOKEN = "token" * 4
        logger.info("Using token: ${TOKEN}")

        // Create the CAService
        CAService cas = new CAService(TOKEN, caKeyPair, caCert)
        logger.info("Created CAService: ${cas}")

        // Create the CAHandler
        CAHandler caHandler = new CAHandler(cas)
        logger.info("Created CAHandler: ${caHandler}")

        // Generate the (mock) CSR
        String csrDn = "CN=node1.nifi.apache.org"
        KeyPair nodeKeyPair = generateKeyPair()
        JcaPKCS10CertificationRequest csr = CAService.generateCSR(csrDn, [], nodeKeyPair)
        logger.info("Generated CSR: ${csr.subject}")

        // Encode the CSR in PEM (Base64)
        String pemEncodedCsr = TlsToolkitUtil.pemEncode(csr)
        logger.info("PEM-encoded CSR: ${pemEncodedCsr}")

        String hmac = TlsToolkitUtil.calculateHMac(TOKEN, nodeKeyPair.public)
        logger.info("Calculated HMAC using token ${TOKEN}: ${hmac}")

        // Wrap the CSR and HMAC in JSON
        String requestJson = JsonOutput.toJson([csr: pemEncodedCsr, hmac: hmac])
        logger.info("Wrapped contents in JSON: ${requestJson}")

        // Form a request
        HttpServletRequest request = [
                getRemoteAddr: { -> "mock://localhost:14443" },
                getReader    : { -> new BufferedReader(new StringReader(requestJson)) }
        ] as HttpServletRequest

        // Build a response object to hold the response
        StringWriter responseSW = new StringWriter()
        String contentType = ""
        int statusCode = 0
        HttpServletResponse response = mockResponse(responseSW, contentType, statusCode)

        // Act
        caHandler.handle("target", new Request(null, null), request, response)
        logger.info("Got response: ${response}")

        // Assert
        assert response.status == Response.SC_OK
        assert response.contentType == "application/json"

        String responseJson = responseSW.toString()
        logger.info("Response JSON: ${responseJson}")

        Map parsedResponse = new JsonSlurper().parseText(responseJson) as Map
        def message = parsedResponse.message
        assert message =~ "Successfully signed certificate"
        logger.info("Message: ${message}")

        String pemEncodedChain = parsedResponse.certificateChain

        List<String> chainElements = splitPEMEncodedCertificateChain(pemEncodedChain)

        List<Certificate> chain = chainElements.collect { TlsToolkitUtil.decodeCertificate(it) }
        assert chain.size() == 2
        X509Certificate returnedCACert = chain.first() as X509Certificate
        logger.info("CA certificate: ${returnedCACert.subjectX500Principal.name}")

        X509Certificate signedCertificate = chain.last() as X509Certificate
        logger.info("Signed certificate: ${signedCertificate.subjectX500Principal.name}")

        assert signedCertificate.publicKey == nodeKeyPair.public
        assert signedCertificate.subjectX500Principal.name == csrDn
        signedCertificate.verify(caKeyPair.public)
        logger.info("The signed certificate was signed by the CA key")
    }

    private HttpServletResponse mockResponse(StringWriter responseSW, String contentType, int statusCode) {
        HttpServletResponse response = [
                getWriter     : { -> new PrintWriter(responseSW) },
                setContentType: { ct ->
                    logger.mock("Set response content type to ${ct}")
                    contentType = ct
                },
                getContentType: { -> contentType },
                setStatus     : { sc ->
                    logger.mock("Set response status code to ${sc}")
                    statusCode = sc
                },
                getStatus     : { -> statusCode }
        ] as HttpServletResponse
        response
    }

    /**
     * Provide CSR object and inject CA service
     */
    @Test
    void testShouldRejectCSRWithInvalidHMAC() {
        // Arrange
        final String CA_CN = "nifi-ca.nifi.apache.org"
        final String CA_DN = "CN=" + CA_CN

        KeyPair caKeyPair = generateKeyPair()

        // Generate the CA
        X509Certificate caCert = CAService.generateCACertificate(caKeyPair, CA_DN)
        logger.info("Issued CA certificate with subject: ${caCert.getSubjectDN().name} and SAN: ${caCert.getSubjectAlternativeNames().join(",")}")

        final String TOKEN = "token" * 4
        logger.info("Using token: ${TOKEN}")

        // Create the CAService
        CAService cas = new CAService(TOKEN, caKeyPair, caCert)
        logger.info("Created CAService: ${cas}")

        // Create the CAHandler
        CAHandler caHandler = new CAHandler(cas)
        logger.info("Created CAHandler: ${caHandler}")

        // Generate the (mock) CSR
        String csrDn = "CN=node1.nifi.apache.org"
        KeyPair nodeKeyPair = generateKeyPair()
        JcaPKCS10CertificationRequest csr = CAService.generateCSR(csrDn, [], nodeKeyPair)
        logger.info("Generated CSR: ${csr.subject}")

        // Encode the CSR in PEM (Base64)
        String pemEncodedCsr = TlsToolkitUtil.pemEncode(csr)
        logger.info("PEM-encoded CSR: ${pemEncodedCsr}")

        String hmac = TlsToolkitUtil.calculateHMac(TOKEN, nodeKeyPair.public)
        logger.info("Calculated HMAC using token ${TOKEN}: ${hmac}")
        hmac = hmac.reverse()
        logger.info("Reversed HMAC to generate exception: ${hmac}")

        // Wrap the CSR and HMAC in JSON
        String requestJson = JsonOutput.toJson([csr: pemEncodedCsr, hmac: hmac])
        logger.info("Wrapped contents in JSON: ${requestJson}")

        // Form a request
        HttpServletRequest request = [
                getRemoteAddr: { -> "mock://localhost:14443" },
                getReader    : { -> new BufferedReader(new StringReader(requestJson)) }
        ] as HttpServletRequest

        // Build a response object to hold the response
        StringWriter responseSW = new StringWriter()
        String contentType = ""
        int statusCode = 0
        HttpServletResponse response = mockResponse(responseSW, contentType, statusCode)

        // Act
        caHandler.handle("target", new Request(null, null), request, response)
        logger.info("Got response: ${response}")

        // Assert
        assert response.status != Response.SC_OK
        assert response.contentType == "application/json"

        String responseJson = responseSW.toString()
        logger.info("Response JSON: ${responseJson}")

        Map parsedResponse = new JsonSlurper().parseText(responseJson) as Map
        def message = parsedResponse.message
        assert message =~ "Unable to sign"
        logger.info("Message: ${message}")

        def errorMessage = parsedResponse.errorMessage
        assert errorMessage =~ "HMAC was not valid"
        logger.info("Error Message: ${errorMessage}")

        String pemEncodedChain = parsedResponse.certificateChain
        assert !pemEncodedChain
        logger.info("No signed certificate returned")
    }

    private static List<String> splitPEMEncodedCertificateChain(String pemEncodedChain) {
        pemEncodedChain.split("(?<=-----)(\n)(?=-----)") as List<String>
    }
}
