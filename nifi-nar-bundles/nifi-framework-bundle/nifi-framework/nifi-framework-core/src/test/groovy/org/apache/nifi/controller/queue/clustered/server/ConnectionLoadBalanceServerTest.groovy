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
package org.apache.nifi.controller.queue.clustered.server

import org.apache.nifi.events.EventReporter
import org.apache.nifi.security.util.KeyStoreUtils
import org.apache.nifi.security.util.KeystoreType
import org.apache.nifi.security.util.SslContextFactory
import org.apache.nifi.security.util.TlsConfiguration
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocketFactory
import java.security.Security

@RunWith(JUnit4.class)
class ConnectionLoadBalanceServerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionLoadBalanceServerTest.class)

    private static final String KEYSTORE_PATH = "src/test/resources/localhost-ks.jks"
    private static final String KEYSTORE_PASSWORD = "OI7kMpWzzVNVx/JGhTL/0uO4+PWpGJ46uZ/pfepbkwI"
    private static final KeystoreType KEYSTORE_TYPE = KeystoreType.JKS

    private static final String TRUSTSTORE_PATH = "src/test/resources/localhost-ts.jks"
    private static final String TRUSTSTORE_PASSWORD = "wAOR0nQJ2EXvOP0JZ2EaqA/n7W69ILS4sWAHghmIWCc"
    private static final KeystoreType TRUSTSTORE_TYPE = KeystoreType.JKS

    private static final String HOSTNAME = "localhost"
    private static final int PORT = 54321
    private static final int NUM_THREADS = 1
    private static final int TIMEOUT_MS = 1000

    private static TlsConfiguration tlsConfiguration
    private static SSLContext sslContext

    private static SSLSocketFactory defaultGroovySocketFactory

    private ConnectionLoadBalanceServer lbServer

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        tlsConfiguration = new TlsConfiguration(KEYSTORE_PATH, KEYSTORE_PASSWORD, KEYSTORE_TYPE, TRUSTSTORE_PATH, TRUSTSTORE_PASSWORD, TRUSTSTORE_TYPE)
        sslContext = SslContextFactory.createSslContext(tlsConfiguration)
    }

    @Before
    void setUp() {
        defaultGroovySocketFactory = HttpsURLConnection.defaultSSLSocketFactory
    }

    @After
    void tearDown() {
        HttpsURLConnection.defaultSSLSocketFactory = defaultGroovySocketFactory

        if (lbServer) {
            lbServer.stop()
        }
    }

    @Test
    void testShouldCreateSecureServer() {
        // Arrange
        logger.info("Creating SSL Context from TLS Configuration: ${tlsConfiguration}")
        SSLContext sslContext = SslContextFactory.createSslContext(tlsConfiguration, SslContextFactory.ClientAuth.NONE)
        logger.info("Created SSL Context: ${KeyStoreUtils.sslContextToString(sslContext)}")

//        def keyManagers = SslContextFactory.getKeyManagers(tlsConfiguration)
//        X509KeyManager x509km = keyManagers.first() as X509KeyManager
//        def aliases = x509km.getServerAliases("RSA", null)
//        def serverCertChain = x509km.getCertificateChain(aliases.first())
//        def serverCert = serverCertChain.first()

        def mockLBP = [
                receiveFlowFiles: { Socket s, InputStream i, OutputStream o -> null }
        ] as LoadBalanceProtocol
        def mockER = [:] as EventReporter

        lbServer = new ConnectionLoadBalanceServer(HOSTNAME, PORT, sslContext, NUM_THREADS, mockLBP, mockER, TIMEOUT_MS)

        // Act
        lbServer.start()

        // Assert

        // Assertion 1 (direct examination of server socket & context)

        // Assert that the default parameters (which can't be modified) still have legacy protocols and no client auth
        def defaultSSLParameters = sslContext.defaultSSLParameters
        logger.info("Default SSL Parameters: ${KeyStoreUtils.sslParametersToString(defaultSSLParameters)}" as String)
        assert defaultSSLParameters.getProtocols() == ["TLSv1.2", "TLSv1.1", "TLSv1"] as String[]
        assert !defaultSSLParameters.needClientAuth

        // Assert that the actual socket is set correctly due to the override in the LB server
        SSLServerSocket socket = lbServer.serverSocket as SSLServerSocket
        logger.info("Created SSL server socket: ${KeyStoreUtils.sslServerSocketToString(socket)}" as String)
        assert socket.enabledProtocols == ["TLSv1.2", "TLSv1.3"] as String[]
        assert socket.needClientAuth

        // Assertion 2 (make external connection to socket)

//        // Custom truststore necessary (only support TLSv1.2 for connection)
//        def clientSslContext = SSLContext.getInstance(CertificateUtils.CURRENT_TLS_PROTOCOL_VERSION)
//        X509TrustManager x509tm = SslContextFactory.getX509TrustManager(tlsConfiguration)
//        clientSslContext.init(null, [x509tm] as TrustManager[], new SecureRandom())
//        HttpsURLConnection.defaultSSLSocketFactory = clientSslContext.socketFactory
//
//        def connection = new URL("https://${HOSTNAME}:${PORT}").openConnection() as HttpURLConnection
//
//        // Set some headers
//        connection.setRequestProperty('User-Agent', 'groovy-2.4.4')
//        connection.setRequestProperty('Accept', 'application/json')
//
//        // Attempt to connect
//        connection.requestMethod = "POST"
//        connection.doOutput = true
//        def text
//        connection.with {
//            outputStream.withWriter { outputStreamWriter ->
//                outputStreamWriter << "Example flowfile content"
//            }
//            text = content.text
//        }
//        logger.info("Connection response code: ${connection.responseCode}")
//
//        assert connection
//        HttpsURLConnection httpsConnection = connection as HttpsURLConnection
//        def serverCertificates = httpsConnection.serverCertificates
//        def cipherSuite = httpsConnection.cipherSuite
//        def certificate = serverCertificates.first() as X509Certificate
//        logger.info("Connected to ${certificate.subjectX500Principal.name} with ${cipherSuite}")
//        assert serverCertificates.contains(serverCert)
//        assert cipherSuite.startsWith("TLS_")

        // Clean up
        lbServer.stop()
    }
}
