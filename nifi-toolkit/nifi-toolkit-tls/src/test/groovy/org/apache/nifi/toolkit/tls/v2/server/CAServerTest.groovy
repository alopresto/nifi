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

import org.apache.nifi.toolkit.tls.v2.ca.CAService
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.jetty.server.Connector
import org.eclipse.jetty.server.Handler
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate

@RunWith(JUnit4.class)
class CAServerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CAServerTest.class)

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder()

    private static final String TOKEN = "token" * 4

    private static final File KEYSTORE_FILE = new File("src/test/resources/v2/localhost/keystore.jks")
    private static final String KEYSTORE_PATH = KEYSTORE_FILE.path
    private static final String KEYSTORE_PASSWORD = "password" * 2
    private static final String ALIAS = "nifi-key"

    private static final File TRUSTSTORE_FILE = new File("src/test/resources/v2/localhost/truststore.jks")
    private static final String TRUSTSTORE_PATH = TRUSTSTORE_FILE.path
    private static final String TRUSTSTORE_PASSWORD = KEYSTORE_PASSWORD

    private static final String EXTERNAL_CA_CERT_PATH = "src/test/resources/v2/nifi-cert.pem"
    private static final String EXTERNAL_CA_KEY_PATH = "src/test/resources/v2/nifi-key.key"

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
     * Verifies that the server is created correctly.
     */
    @Test
    void testShouldCreateServer() {
        // Arrange
        CAHandler mockHandler = [:] as CAHandler
        final int PORT = 14443

        KeyStore keystore = KeyStore.getInstance("JKS")
        keystore.load(KEYSTORE_FILE.newInputStream(), KEYSTORE_PASSWORD.chars)
        logger.info("Loaded keystore ${keystore} from ${KEYSTORE_PATH}")

        // Act
        Server server = CAServer.createServer(mockHandler, PORT, keystore, KEYSTORE_PASSWORD)
        logger.info("Created server: ${server}")

        // Assert
        def connectors = server.connectors as List<Connector>
        assert connectors.size() == 1
        def httpsConnector = connectors.first()
        assert httpsConnector.protocols.contains("ssl")
//        assert httpsConnector.defaultConnectionFactory.protocols == ["TLSv1.2"]
        assert (httpsConnector as ServerConnector).port == 14443
    }

    /**
     * Verifies that the service is created with the existing keystore
     */
    @Test
    void testShouldCreateCAServiceWithKeystore() {
        // Arrange
        KeyStore keystore = KeyStore.getInstance("JKS")
        keystore.load(KEYSTORE_FILE.newInputStream(), KEYSTORE_PASSWORD.chars)
        logger.info("Loaded keystore ${keystore} from ${KEYSTORE_PATH}")

        // Act
        CAService caService = CAServer.createCAService(keystore, KEYSTORE_PASSWORD, TOKEN, ALIAS)
        logger.info("Created CAService: ${caService}")

        // Assert
        assert caService.caCert == keystore.getCertificate(ALIAS)
    }

    /**
     * Verifies that the server is created with the existing keystore
     */
    @Test
    void testShouldLocateExistingKeystore() {
        // Arrange
        KeyStore EXPECTED_KEYSTORE = KeyStore.getInstance("JKS")
        EXPECTED_KEYSTORE.load(KEYSTORE_FILE.newInputStream(), KEYSTORE_PASSWORD.chars)
        logger.info("Loaded expected keystore ${EXPECTED_KEYSTORE} from ${KEYSTORE_PATH}")

        // Act
        KeyStore keystore = CAServer.generateOrLocateKeystore(KEYSTORE_PATH, KEYSTORE_PASSWORD, ALIAS, CAServer.DEFAULT_DN)
        logger.info("Created keystore: ${keystore}")

        // Assert
        assert keystore.getCertificate(ALIAS) == EXPECTED_KEYSTORE.getCertificate(ALIAS)
        assert keystore.getKey(ALIAS, KEYSTORE_PASSWORD.chars) == EXPECTED_KEYSTORE.getKey(ALIAS, KEYSTORE_PASSWORD.chars)
    }

    /**
     * Verifies that the service is created if the provided keystore does not exist
     */
    @Test
    void testShouldGenerateNewKeystore() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String TMP_KEYSTORE_PATH = keystoreFile.path
        keystoreFile.delete()
        logger.info("Keystore exists at ${TMP_KEYSTORE_PATH}: ${keystoreFile.exists()}")

        // Act
        KeyStore keystore = CAServer.generateOrLocateKeystore(TMP_KEYSTORE_PATH, KEYSTORE_PASSWORD, ALIAS, CAServer.DEFAULT_DN)
        logger.info("Created keystore: ${keystore}")

        // Assert
        def caCert = keystore.getCertificate(ALIAS) as X509Certificate
        assert caCert.subjectX500Principal as String == CAServer.DEFAULT_DN

        // Implicitly asserts that the password is correct
        assert keystore.getKey(ALIAS, KEYSTORE_PASSWORD.chars) instanceof PrivateKey

        // Assert that the keystore file was persisted to the provided path
        KeyStore persistedKeystore = KeyStore.getInstance("JKS")
        File persistedKeystoreFile = new File(TMP_KEYSTORE_PATH)
        persistedKeystore.load(persistedKeystoreFile.newInputStream(), KEYSTORE_PASSWORD.chars)
        logger.info("Loaded keystore from ${TMP_KEYSTORE_PATH}")
    }

    /**
     * Verifies that the service is created if the provided keystore does not exist
     */
    @Test
    void testShouldCreateCAServiceWithoutKeystore() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String TMP_KEYSTORE_PATH = keystoreFile.path
        keystoreFile.delete()
        logger.info("Keystore exists at ${TMP_KEYSTORE_PATH}: ${keystoreFile.exists()}")

        // Act
        CAServer caServer = new CAServer(14443, TMP_KEYSTORE_PATH, KEYSTORE_PASSWORD, TOKEN)
        logger.info("Created CAServer: ${caServer}")

        // Assert
        def caHandler = (caServer.server.handlers as List<Handler>).first() as CAHandler
        def caCert = caHandler.getCACertificate()
        logger.info("CA cert in CAHandler: ${caCert}")
        logger.info("CA cert name in CAHandler: ${caHandler.getCACertificateSubjectName()}")

        assert caHandler.getCACertificateSubjectName() == CAServer.DEFAULT_DN

        // Assert that the keystore file was persisted to the provided path
        KeyStore persistedKeystore = KeyStore.getInstance("JKS")
        File persistedKeystoreFile = new File(TMP_KEYSTORE_PATH)
        // Implicitly asserts that the password is correct
        persistedKeystore.load(persistedKeystoreFile.newInputStream(), KEYSTORE_PASSWORD.chars)
        logger.info("Loaded keystore from ${TMP_KEYSTORE_PATH}")
    }
}
