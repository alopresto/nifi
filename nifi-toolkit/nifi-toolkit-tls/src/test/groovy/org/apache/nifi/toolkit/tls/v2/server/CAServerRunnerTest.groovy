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

import groovy.json.JsonBuilder
import groovyx.net.http.NativeHandlers
import org.apache.commons.cli.CommandLine
import org.apache.nifi.security.util.CertificateUtils
import org.apache.nifi.security.util.SslContextFactory
import org.apache.nifi.toolkit.tls.v2.ca.CAService
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.contrib.java.lang.system.ExpectedSystemExit
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.security.auth.x500.X500Principal
import java.math.MathContext
import java.security.KeyPair
import java.security.KeyStore
import java.security.PublicKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate

import static groovyx.net.http.ContentTypes.JSON
import static groovyx.net.http.HttpBuilder.configure

@RunWith(JUnit4.class)
class CAServerRunnerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CAServerRunnerTest.class)

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder()

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none()

    private static final String TOKEN = "token" * 4
    private static final File KEYSTORE_FILE = new File("src/test/resources/v2/localhost/keystore.jks")
    private static final String KEYSTORE_PATH = KEYSTORE_FILE.path
    private static final String KEYSTORE_PASSWORD = "password" * 2

    private static final File TRUSTSTORE_FILE = new File("src/test/resources/v2/localhost/truststore.jks")
    private static final String TRUSTSTORE_PATH = TRUSTSTORE_FILE.path
    private static final String TRUSTSTORE_PASSWORD = KEYSTORE_PASSWORD

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
     * Returns a {@link BufferedReader} that mocks {@code System.in} so the shutdown command can be sent. Waits ~ {@code seconds} seconds before sending (adds a newline char per every 5 seconds of waiting).
     *
     * @param seconds the amount of time to let the server run (resolution of ~5 s, default 10 s)
     * @return the reader to provide
     */
    private static BufferedReader generateShutdownReader(int seconds = 10) {
        // One newline character per 5 second delay
        String delay = "\n" * (seconds / 5)
        new BufferedReader(new StringReader("${delay}stop\n"))
    }

    /**
     * Verifies that a valid token param is required.
     */
    @Test
    void testParseShouldRequireToken() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String TMP_KEYSTORE_PATH = keystoreFile.path

        CAServerRunner runner = new CAServerRunner()

        def args = "-k ${TMP_KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine tokenCL = runner.parse(args as String[])
        logger.info("Parsed command line from args ${args}: ${tokenCL}")

        def msg = shouldFail {
            CommandLine noTokenCL = runner.parse(new String[0])
        }
        logger.expected(msg)

        // Assert
        assert tokenCL.getOptionValue(CAServerRunner.TOKEN_ARG) == TOKEN
    }

    /**
     * Verifies that the keystore path and password are present.
     */
    @Test
    void testShouldParseKeystoreArgs() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String TMP_KEYSTORE_PATH = keystoreFile.path

        CAServerRunner runner = new CAServerRunner()

        def args = "-k ${TMP_KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine cl = runner.parse(args as String[])
        logger.info("Parsed command line from args ${args}: ${cl}")

        // Assert
        assert cl.getOptionValue(CAServerRunner.KEYSTORE_PATH_ARG) == TMP_KEYSTORE_PATH
        assert cl.getOptionValue(CAServerRunner.KEYSTORE_PASSWORD_ARG) == KEYSTORE_PASSWORD
    }

    /**
     * Verifies that if the keystore path is not present, external CA PEM files are loaded.
     */
    @Test
    void testParseShouldRequireExternalCAFilesIfKeystoreMissing() {
        // Arrange
        File certFile = tmpDir.newFile("cert.pem")
        final String CERT_PATH = certFile.path
        File keyFile = tmpDir.newFile("cert.key")
        final String KEY_PATH = keyFile.path

        CAServerRunner runner = new CAServerRunner()

        def args = "-c ${CERT_PATH} -K ${KEY_PATH} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine cl = runner.parse(args as String[])
        logger.info("Parsed command line from args ${args}: ${cl}")

        // Assert
        assert cl.getOptionValue(CAServerRunner.EXTERNAL_CA_CERT_PATH_ARG) == CERT_PATH
        assert cl.getOptionValue(CAServerRunner.EXTERNAL_CA_KEY_PATH_ARG) == KEY_PATH

        assert !cl.getOptionValue(CAServerRunner.KEYSTORE_PATH_ARG)
        assert !cl.getOptionValue(CAServerRunner.KEYSTORE_PASSWORD_ARG)
    }

    /**
     * Verifies that an existing keystore can be successfully loaded.
     */
    @Test
    void testShouldLoadExistingKeystore() {
        // Arrange
        final String EXPECTED_ALIAS = "nifi-key"
        final String EXPECTED_DN = "CN=localhost, OU=NiFi CA"
        final KeyStore EXPECTED_KEYSTORE = KeyStore.getInstance("JKS")
        EXPECTED_KEYSTORE.load(KEYSTORE_FILE.newInputStream(), KEYSTORE_PASSWORD.chars)
        final PublicKey EXPECTED_PUBLIC_KEY = EXPECTED_KEYSTORE.getCertificate(EXPECTED_ALIAS).publicKey

        CAServerRunner runner = new CAServerRunner()

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        CommandLine cl = runner.parse(args as String[])
        logger.info("Parsed command line from args ${args}: ${cl}")

        // Act
        KeyStore keystore = runner.prepareKeystore()
        logger.info("Loaded keystore: ${keystore}")

        // Assert
        assert keystore.containsAlias(EXPECTED_ALIAS)
        def certificate = keystore.getCertificate(EXPECTED_ALIAS) as X509Certificate
        logger.info("Loaded certificate at alias ${EXPECTED_ALIAS} with subject ${certificate.subjectX500Principal} and public key ${certificate.publicKey}")
        assert certificate.subjectX500Principal.toString() == EXPECTED_DN
        assert certificate.publicKey == EXPECTED_PUBLIC_KEY
    }

    /**
     * Starts the server with an existing keystore, runs for ~5 seconds, and then stops it.
     */
    @Test
    void testShouldStartAndShutdownServer() {
        // Arrange
        exit.expectSystemExitWithStatus(0)

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Override the shutdown reader
        int runTime = 5
        CAServerRunner.shutdownReader = generateShutdownReader(runTime)
        logger.info("Configured server to run for ~ ${runTime} s")

        long start, stop
        exit.checkAssertionAfterwards({
            logger.info("Ran main() with args: ${args}")

            stop = System.nanoTime()
            logger.stop("${stop}")

            long executionTimeMs = (stop - start) / 1_000_000
            logger.info("Server ran for ${executionTimeMs} ms (${(executionTimeMs / 1_000).round(new MathContext(3))}) s")
            assert executionTimeMs > runTime * 1_000
        })

        // Act
        start = System.nanoTime()
        logger.start("${start}")

        CAServerRunner.main(args)

        // Assert

        // Assertions defined above
    }

    /**
     * Start the server, send an HTTP request with a CSR, and receive and verify the signed certificate chain.
     */
    @Test
    void testShouldSignCSR() {
        // Arrange
        exit.expectSystemExitWithStatus(0)

        // Configure the request builder
        def http = configure {
            request.uri = 'https://localhost:14443'
            request.contentType = 'application/json'

            // Build the TLS configs
            execution.sslContext = generateLocalhostTrustContext()
            execution.hostnameVerifier = generateLocalhostVerifier()

            // Configure the JSON parser for the result
            request.contentType = JSON[0]
            response.parser(JSON[0]) { config, resp ->
                NativeHandlers.Parsers.json(config, resp)
            }
        }

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Override the shutdown reader
        int runTime = 5
        CAServerRunner.shutdownReader = generateShutdownReader(runTime)
        logger.info("Configured server to run for ~ ${runTime} s")

        // Build the CSR
        String nodeDn = "CN=node.nifi.apache.org, OU=NiFi"
        KeyPair nodeKeyPair = TlsToolkitUtil.generateKeyPair()
        def csr = CAService.generateCSR(nodeDn, [], nodeKeyPair)
        logger.info("Created CSR: ${csr.subject}")

        // Encode the CSR as PEM (Base64)
        String pemEncodedCsr = TlsToolkitUtil.pemEncode(csr)
        logger.info("PEM encoded CSR: ${pemEncodedCsr}")

        // Generate the HMAC
        String hmac = TlsToolkitUtil.calculateHMac(TOKEN, csr.publicKey)
        logger.info("Calculated HMAC of CSR public key: ${hmac}")

        // Build the request
        Map requestMap = [hmac: hmac, csr: pemEncodedCsr]
        String requestJson = new JsonBuilder(requestMap).toString()
        logger.info("Generated request JSON: ${requestJson}")

        long start, stop
        exit.checkAssertionAfterwards({
            logger.info("Ran main() with args: ${args}")

            stop = System.nanoTime()
            logger.stop("${stop}")

            long executionTimeMs = (stop - start) / 1_000_000
            logger.info("Server ran for ${executionTimeMs} ms (${(executionTimeMs / 1_000).round(new MathContext(3))}) s")
            assert executionTimeMs > runTime * 1_000

            // TODO: Check that received certificate was signed correctly and response format is good
        })

        // Act

        // Send the request in a separate thread
        Thread.start("client") {
            // Wait for the server to come online
            sleep(2000)

            // Send the request
            Map response = http.post(Map) {
                request.body = requestJson
//            response.success { FromServer fs ->
//                logger.success(fs.statusCode)
//            }
//            response.failure { FromServer fs ->
//                logger.failure(fs.statusCode)
//            }
            }
            logger.info("Response: ${response}")

            // Assert

            assert response.message =~ "Successfully signed certificate"

            def certChain = TlsToolkitUtil.splitPEMEncodedCertificateChain(response.certificateChain)
            assert certChain.size() == 2

            // Assert the node cert is signed by the root cert
            certChain.last().verify(certChain.first().publicKey)
        }

        // Start the server
        start = System.nanoTime()
        logger.start("${start}")

        CAServerRunner.main(args)

        // Assert

        // Server assertions defined above
    }

    /**
     * Returns an {@link SSLContext} which uses the test resource truststore.
     *
     * @return the context
     */
    private static SSLContext generateLocalhostTrustContext() {
        SslContextFactory.createTrustSslContext(TRUSTSTORE_PATH, TRUSTSTORE_PASSWORD.chars, "JKS", "TLSv1.2")
    }

    /**
     * Returns a simple {@link HostnameVerifier} which validates the hostname against any SAN entries (and CN if no SANS present).
     *
     * @return the verifier
     */
    private static HostnameVerifier generateLocalhostVerifier() {
        [verify: { String hostname, SSLSession session ->
            def certs = session.getPeerCertificates() as List<Certificate>
            def presentedHostnames = getPresentedHostnames(certs.first() as X509Certificate)
            logger.mock("Verifying ${hostname} against ${presentedHostnames}")
        }] as HostnameVerifier
    }

    /**
     * Returns a parsed list of the SAN entries, and if none are present, includes the CN.
     *
     * @param cert the certificate
     * @return
     */
    private static List<String> getPresentedHostnames(X509Certificate cert) {
        def sans = cert.getSubjectAlternativeNames().collect { List entry ->
            if (entry.first().toString() in "1,2,6,7".tokenize(",")) {
                entry.last().toString()
            }
        }
        if (!sans) {
            logger.warn("Cert SANS empty; using CN")
            sans = [CertificateUtils.getCNFromDN(cert.subjectX500Principal.getName(X500Principal.RFC2253))]
        }
        logger.info("Determined cert hostnames: [${sans.join(",")}]")
        sans
    }
}
