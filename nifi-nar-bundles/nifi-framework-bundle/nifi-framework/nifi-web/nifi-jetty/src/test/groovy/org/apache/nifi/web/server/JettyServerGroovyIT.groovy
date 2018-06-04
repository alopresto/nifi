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
package org.apache.nifi.web.server

import groovy.test.GroovyAssert
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContexts
import org.apache.nifi.bundle.Bundle
import org.apache.nifi.properties.NiFiPropertiesLoader
import org.apache.nifi.properties.StandardNiFiProperties
import org.apache.nifi.util.NiFiProperties
import org.apache.nifi.web.server.tls.DefaultTlsConfiguration
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Assume
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.contrib.java.lang.system.ExpectedSystemExit
import org.junit.contrib.java.lang.system.SystemErrRule
import org.junit.contrib.java.lang.system.SystemOutRule
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.SocketFactory
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import java.security.Security

@RunWith(JUnit4.class)
class JettyServerGroovyIT extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(JettyServerGroovyTest.class)

    private static final String DEFAULT_HOSTNAME = "localhost"
    private static final int DEFAULT_TLS_PORT = 9443
    private static final String HTTPS_URL = "https://${DEFAULT_HOSTNAME}:${DEFAULT_TLS_PORT}"

    private static final String TEST_RSC_DIR = "src/test/resources/JettyServerGroovyIntegrationTest"
    static private final String KEYSTORE_PASSWORD = "passwordpassword"
    static private final String TRUSTSTORE_PASSWORD = "passwordpassword"

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none()

    @Rule
    public final SystemOutRule systemOutRule = new SystemOutRule().enableLog()

    @Rule
    public final SystemErrRule systemErrRule = new SystemErrRule().enableLog()


    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @AfterClass
    static void tearDownOnce() throws Exception {

    }

    @Before
    void setUp() throws Exception {

    }

    @After
    void tearDown() throws Exception {
    }

    @Test
    void testConstructorShouldLoadDefaultTlsConfigurationProvider() {
        // Arrange
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        final DefaultTlsConfiguration DEFAULT_TLS_CONF = new DefaultTlsConfiguration()
        List<String> RESTRICTED_PROTOCOLS = DEFAULT_TLS_CONF.protocols - ["TLSv1", "TLSv1.1"]

        // Act
        JettyServer jetty = new JettyServer(httpsProps, [] as Set<Bundle>)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled server cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled server protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Assert
        assert enabledCipherSuites == DEFAULT_TLS_CONF.cipherSuites
        assert enabledProtocols == RESTRICTED_PROTOCOLS
    }

    @Test
    void testDefaultServerShouldRejectLegacyProtocolConnections() {
        // Arrange
        NiFiProperties httpsProps = new NiFiPropertiesLoader().load("${TEST_RSC_DIR}/nifi.properties")

        JettyServer jetty = new JettyServer(httpsProps, [] as Set<Bundle>)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled server cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled server protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Manually start the internal server
        try {
            jetty.server.start()
        } catch (BindException e) {
            logger.warn("Cannot run this test because a service is already using port 9443")
            Assume.assumeTrue("Cannot run this test because a service is already using port 9443", false)
        }

        // Act
        Exception exception = GroovyAssert.shouldFail(SSLHandshakeException) {
            SSLSocket socket = createSslSocket("TLSv1.1", HTTPS_URL)
            logger.info("Enabled socket protocols: ${socket.enabledProtocols}")

            socket.startHandshake()
            String selectedProtocol = socket.getSession().protocol
            logger.info("Selected socket protocol: ${selectedProtocol}")
        }

        logger.expected("Error: ${exception}")

        // Assert
        assert exception.getMessage() =~ "Received fatal alert: handshake_failure"
        // The exception points to itself as the cause but the underlying cause is javax.net.ssl.SSLHandshakeException: Client requested protocol TLSv1.1 not enabled or not supported
//        assert exception.getCause().getMessage() =~ "Client requested protocol TLSv1.1 not enabled or not supported"

        if (jetty.server.isRunning()) {
            jetty.server.stop()
        }
    }

    /**
     * Run with {@code -Djavax.net.debug=ssl,handshake} for debugging if necessary
     */
    @Test
    void testDefaultServerShouldAcceptModernProtocolConnections() {
        // Arrange
        NiFiProperties httpsProps = new NiFiPropertiesLoader().load("${TEST_RSC_DIR}/nifi.properties")

        JettyServer jetty = new JettyServer(httpsProps, [] as Set<Bundle>)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled server cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled server protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Manually start the internal server
        try {
            jetty.server.start()
        } catch (BindException e) {
            logger.warn("Cannot run this test because a service is already using port 9443")
            Assume.assumeTrue("Cannot run this test because a service is already using port 9443", false)
        }

        SSLSocket socket = createSslSocket("TLSv1.2", HTTPS_URL)
        logger.info("Enabled socket protocols: ${socket.enabledProtocols}")

        // Act
        socket.startHandshake()
        String selectedProtocol = socket.getSession().protocol
        logger.info("Selected socket protocol: ${selectedProtocol}")

        // Assert
        assert selectedProtocol == "TLSv1.2"

        if (jetty.server.isRunning()) {
            jetty.server.stop()
        }
    }

    /**
     * Run with {@code -Djavax.net.debug=ssl,handshake} for debugging if necessary
     */
    @Test
    void testDefaultServerShouldRestrictCipherSuitesFromJavaSecurity() {
        // Arrange

        // Set to true if you have copied src/test/resources/JettyServerGroovyIntegrationTest/java.security to $JAVA_HOME/jre/lib/security/java.security
        boolean restrictedJavaSecurityInUse = true

        Assume.assumeTrue("This test requires a custom java.security file to be used", restrictedJavaSecurityInUse)

        /*
        With the custom java.security file in place, there will be debug output like:
        18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_128_GCM_SHA256' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_256_GCM_SHA384' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_128_CBC_SHA256' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_256_CBC_SHA256' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_128_CBC_SHA' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_AES_256_CBC_SHA' is supported
18/05/25 20:51:01 INFO ssl.SslContextFactory: No Cipher matching 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' is supported
18/05/25 20:51:01 DEBUG ssl.SslContextFactory: Selected Protocols [TLSv1.2] of [SSLv2Hello, SSLv3, TLSv1, TLSv1.1, TLSv1.2]
18/05/25 20:51:01 DEBUG ssl.SslContextFactory: Selected Ciphers   [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256] of [TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, SSL_RSA_WITH_3DES_EDE_CBC_SHA,
TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_EMPTY_RENEGOTIATION_INFO_SCSV, TLS_DH_anon_WITH_AES_256_GCM_SHA384,
TLS_DH_anon_WITH_AES_128_GCM_SHA256, TLS_DH_anon_WITH_AES_256_CBC_SHA256, TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
TLS_DH_anon_WITH_AES_256_CBC_SHA, TLS_DH_anon_WITH_AES_128_CBC_SHA256, TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
TLS_DH_anon_WITH_AES_128_CBC_SHA, TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
SSL_RSA_WITH_DES_CBC_SHA, SSL_DHE_RSA_WITH_DES_CBC_SHA, SSL_DHE_DSS_WITH_DES_CBC_SHA, SSL_DH_anon_WITH_DES_CBC_SHA,
SSL_RSA_EXPORT_WITH_DES40_CBC_SHA, SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_RSA_WITH_NULL_SHA256, TLS_ECDHE_ECDSA_WITH_NULL_SHA,
TLS_ECDHE_RSA_WITH_NULL_SHA, SSL_RSA_WITH_NULL_SHA, TLS_ECDH_ECDSA_WITH_NULL_SHA, TLS_ECDH_RSA_WITH_NULL_SHA,
TLS_ECDH_anon_WITH_NULL_SHA, SSL_RSA_WITH_NULL_MD5, TLS_KRB5_WITH_3DES_EDE_CBC_SHA, TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
TLS_KRB5_WITH_DES_CBC_SHA, TLS_KRB5_WITH_DES_CBC_MD5, TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5]
         */

        NiFiProperties httpsProps = new NiFiPropertiesLoader().load("${TEST_RSC_DIR}/nifi.properties")

        // Act
        JettyServer jetty = new JettyServer(httpsProps, [] as Set<Bundle>)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled server cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled server protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Assert
        assert enabledProtocols == ["TLSv1.2"]
        assert enabledCipherSuites == ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                       "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                                       "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                                       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                                       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                                       "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                                       "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                                       "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"]
    }

    private static SSLSocket createSslSocket(String protocol = "TLS", String url) {
        HostnameVerifier nullHostnameVerifier = [
                verify: { String hostname, session ->
                    // Will always return true if the hostname is "localhost"
                    hostname.equalsIgnoreCase(DEFAULT_HOSTNAME)
                }
        ] as HostnameVerifier

        File clientKeystoreFile = new File("${TEST_RSC_DIR}/CN=user_OU=NIFI-4881.p12")
        File truststoreFile = new File("${TEST_RSC_DIR}/truststore.jks")

        // Trust own CA and all self-signed certs
        SSLContext clientCertSSLContext = SSLContexts.custom()
                .setProtocol(protocol)
                .loadKeyMaterial(clientKeystoreFile, KEYSTORE_PASSWORD.toCharArray(), KEYSTORE_PASSWORD.toCharArray())
                .loadTrustMaterial(truststoreFile, TRUSTSTORE_PASSWORD.toCharArray(), TrustSelfSignedStrategy.INSTANCE)
                .build()

        SocketFactory socketFactory = clientCertSSLContext.getSocketFactory()
        HttpsURLConnection.setDefaultSSLSocketFactory(socketFactory)
        HttpsURLConnection.setDefaultHostnameVerifier(nullHostnameVerifier)

        URL formedUrl = new URL(url)
        SSLSocket socket = (SSLSocket) socketFactory.createSocket(formedUrl.host, formedUrl.port)
        socket
    }
}