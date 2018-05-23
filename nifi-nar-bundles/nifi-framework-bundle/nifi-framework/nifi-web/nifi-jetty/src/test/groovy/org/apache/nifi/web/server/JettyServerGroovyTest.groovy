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

import org.apache.log4j.AppenderSkeleton
import org.apache.log4j.spi.LoggingEvent
import org.apache.nifi.bundle.Bundle
import org.apache.nifi.properties.StandardNiFiProperties
import org.apache.nifi.util.NiFiProperties
import org.apache.nifi.web.server.tls.TlsConfiguration
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.jetty.server.Connector
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.contrib.java.lang.system.Assertion
import org.junit.contrib.java.lang.system.ExpectedSystemExit
import org.junit.contrib.java.lang.system.SystemErrRule
import org.junit.contrib.java.lang.system.SystemOutRule
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class JettyServerGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(JettyServerGroovyTest.class)

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none()

    @Rule
    public final SystemOutRule systemOutRule = new SystemOutRule().enableLog()

    @Rule
    public final SystemErrRule systemErrRule = new SystemErrRule().enableLog()
    private final String EXAMPLE_SC_DUMP = """ SslContextFactory@4de41af9(null,null) trustAll=false
+- Protocol Selections
|   +- Enabled (size=3)
|   |   +- TLSv1
|   |   +- TLSv1.1
|   |   +- TLSv1.2
|   +- Disabled (size=2)
|       +- SSLv2Hello - ConfigExcluded:'SSLv2Hello'
|       +- SSLv3 - JreDisabled:java.security, ConfigExcluded:'SSLv3'
+- Cipher Suite Selections
 +- Enabled (size=29)
 |   +- TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
 |   +- TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
 |   +- TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
 |   +- TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
 |   +- TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 |   +- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 |   +- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 |   +- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 |   +- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 |   +- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 |   +- TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 |   +- TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 |   +- TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 |   +- TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 |   +- TLS_EMPTY_RENEGOTIATION_INFO_SCSV
 |   +- TLS_RSA_WITH_AES_128_CBC_SHA256
 |   +- TLS_RSA_WITH_AES_128_GCM_SHA256
 |   +- TLS_RSA_WITH_AES_256_CBC_SHA256
 |   +- TLS_RSA_WITH_AES_256_GCM_SHA384
 +- Disabled (size=53)
     +- SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DHE_DSS_WITH_DES_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DHE_RSA_WITH_DES_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DH_anon_WITH_3DES_EDE_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_DH_anon_WITH_DES_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_RSA_EXPORT_WITH_DES40_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_RSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_RSA_WITH_DES_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_RSA_WITH_NULL_MD5 - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- SSL_RSA_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DHE_DSS_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DHE_DSS_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DHE_RSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DHE_RSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DH_anon_WITH_AES_128_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DH_anon_WITH_AES_128_CBC_SHA256 - JreDisabled:java.security
     +- TLS_DH_anon_WITH_AES_128_GCM_SHA256 - JreDisabled:java.security
     +- TLS_DH_anon_WITH_AES_256_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_DH_anon_WITH_AES_256_CBC_SHA256 - JreDisabled:java.security
     +- TLS_DH_anon_WITH_AES_256_GCM_SHA384 - JreDisabled:java.security
     +- TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_ECDSA_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDHE_RSA_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_ECDSA_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_RSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_RSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_RSA_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_anon_WITH_AES_128_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_anon_WITH_AES_256_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_ECDH_anon_WITH_NULL_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_WITH_3DES_EDE_CBC_MD5 - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_WITH_3DES_EDE_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_WITH_DES_CBC_MD5 - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_KRB5_WITH_DES_CBC_SHA - JreDisabled:java.security, ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_RSA_WITH_AES_128_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_RSA_WITH_AES_256_CBC_SHA - ConfigExcluded:'^.*_(MD5|SHA|SHA1)\$'
     +- TLS_RSA_WITH_NULL_SHA256 - JreDisabled:java.security
"""
    final List<String> EXPECTED_CS = [
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
    ]
    final int EXPECTED_CS_COUNT = EXPECTED_CS.size()
    final List<String> EXPECTED_PROTOCOLS = ["TLSv1", "TLSv1.1", "TLSv1.2"]
    final int EXPECTED_PROTOCOLS_COUNT = EXPECTED_PROTOCOLS.size()

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        TestAppender.reset()
    }

    @AfterClass
    static void tearDownOnce() throws Exception {

    }

    @Before
    void setUp() throws Exception {

    }

    @After
    void tearDown() throws Exception {
        TestAppender.reset()
    }

    @Test
    void testShouldDetectHttpAndHttpsConfigurationsBothPresent() {
        // Arrange
        Map badProps = [
                (NiFiProperties.WEB_HTTP_HOST) : "localhost",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
                (NiFiProperties.WEB_THREADS)   : NiFiProperties.DEFAULT_WEB_THREADS
        ]
        NiFiProperties mockProps = [
                getPort    : { -> 8080 },
                getSslPort : { -> 8443 },
                getProperty: { String prop ->
                    String value = badProps[prop] ?: "no_value"
                    logger.mock("getProperty(${prop}) -> ${value}")
                    value
                },
        ] as StandardNiFiProperties

        // Act
        boolean bothConfigsPresent = JettyServer.bothHttpAndHttpsConnectorsConfigured(mockProps)
        logger.info("Both configs present: ${bothConfigsPresent}")
        def log = TestAppender.getLogLines()

        // Assert
        assert bothConfigsPresent
        assert !log.isEmpty()
        assert log.first() =~ "Both the HTTP and HTTPS connectors are configured in nifi.properties. Only one of these connectors should be configured. See the NiFi Admin Guide for more details"
    }

    @Test
    void testDetectHttpAndHttpsConfigurationsShouldAllowEither() {
        // Arrange
        Map httpMap = [
                (NiFiProperties.WEB_HTTP_HOST) : "localhost",
                (NiFiProperties.WEB_HTTPS_HOST): null,
        ]
        NiFiProperties httpProps = [
                getPort    : { -> 8080 },
                getSslPort : { -> null },
                getProperty: { String prop ->
                    String value = httpMap[prop] ?: "no_value"
                    logger.mock("getProperty(${prop}) -> ${value}")
                    value
                },
        ] as StandardNiFiProperties

        Map httpsMap = [
                (NiFiProperties.WEB_HTTP_HOST) : null,
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]
        NiFiProperties httpsProps = [
                getPort    : { -> null },
                getSslPort : { -> 8443 },
                getProperty: { String prop ->
                    String value = httpsMap[prop] ?: "no_value"
                    logger.mock("getProperty(${prop}) -> ${value}")
                    value
                },
        ] as StandardNiFiProperties

        // Act
        boolean bothConfigsPresentForHttp = JettyServer.bothHttpAndHttpsConnectorsConfigured(httpProps)
        logger.info("Both configs present for HTTP properties: ${bothConfigsPresentForHttp}")

        boolean bothConfigsPresentForHttps = JettyServer.bothHttpAndHttpsConnectorsConfigured(httpsProps)
        logger.info("Both configs present for HTTPS properties: ${bothConfigsPresentForHttps}")
        def log = TestAppender.getLogLines()

        // Assert
        assert !bothConfigsPresentForHttp
        assert !bothConfigsPresentForHttps

        // Verifies that the warning was not logged
        assert log.size() == 2
        assert log.first() == "Both configs present for HTTP properties: false"
        assert log.last() == "Both configs present for HTTPS properties: false"
    }

    @Test
    void testShouldFailToStartWithHttpAndHttpsConfigurationsBothPresent() {
        // Arrange
        Map badProps = [
                (NiFiProperties.WEB_HTTP_HOST) : "localhost",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]
        NiFiProperties mockProps = [
                getPort            : { -> 8080 },
                getSslPort         : { -> 8443 },
                getProperty        : { String prop ->
                    String value = badProps[prop] ?: "no_value"
                    logger.mock("getProperty(${prop}) -> ${value}")
                    value
                },
                getWebThreads      : { -> NiFiProperties.DEFAULT_WEB_THREADS },
                getWebMaxHeaderSize: { -> NiFiProperties.DEFAULT_WEB_MAX_HEADER_SIZE },
                isHTTPSConfigured  : { -> true }
        ] as StandardNiFiProperties

        // The web server should fail to start and exit Java
        exit.expectSystemExitWithStatus(1)
        exit.checkAssertionAfterwards(new Assertion() {
            void checkAssertion() {
                final String standardErr = systemErrRule.getLog()
                List<String> errLines = standardErr.split("\n")

                assert errLines.any { it =~ "Failed to start web server: " }
                assert errLines.any { it =~ "Shutting down..." }
            }
        })

        // Act
        JettyServer jettyServer = new JettyServer(mockProps, [] as Set<Bundle>)

        // Assert

        // Assertions defined above
    }

    @Test
    void testShouldConfigureHTTPSConnector() {
        // Arrange
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
//               (NiFiProperties.WEB_HTTP_PORT): null,
//               (NiFiProperties.WEB_HTTP_HOST): null,
(NiFiProperties.WEB_HTTPS_PORT): "8443",
(NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        // Act
        jetty.configureHttpsConnector(internalServer, new HttpConfiguration())
        List<Connector> connectors = Arrays.asList(internalServer.connectors)

        // Assert
        assert connectors.size() == 1
        ServerConnector connector = connectors.first() as ServerConnector
        assert connector.host == "secure.host.com"
        assert connector.port == 8443
    }

    @Test
    void testShouldConfigureHTTPSConnectorWithTlsConfiguration() {
        // Arrange
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
//               (NiFiProperties.WEB_HTTP_PORT): null,
//               (NiFiProperties.WEB_HTTP_HOST): null,
(NiFiProperties.WEB_HTTPS_PORT): "8443",
(NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        // Mock and inject the TLS configuration
        TlsConfiguration mockTls = [
                getCipherSuites: { -> ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] },
                getProtocols   : { -> ["TLSv1.2"] }
        ] as TlsConfiguration
        jetty.tlsConfiguration = mockTls

        // Act
        jetty.configureHttpsConnector(internalServer, new HttpConfiguration())
        List<Connector> connectors = Arrays.asList(internalServer.connectors)

        // Assert
        ServerConnector connector = connectors.first() as ServerConnector
        assert connector.host == "secure.host.com"
        // TODO: Determine how to get cipher suites from connector or server
    }

    private static ServerConnector createDefaultServerConnector() {
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        jetty.configureHttpsConnector(internalServer, new HttpConfiguration())
        List<Connector> connectors = Arrays.asList(internalServer.connectors)
        connectors.first() as ServerConnector
    }

    @Test
    void testShouldExtractEnabledCipherSuitesFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> cipherSuites = EXPECTED_CS
        int csCount = EXPECTED_CS_COUNT

//        ServerConnector sc = createDefaultServerConnector()

        // List<String> dump = sc?.getDefaultConnectionFactory()?._sslContextFactory?.dump().split("\n")

        // Act
        List<String> enabledCipherSuites = getEnabledCipherSuitesFromConnectorDump(dump)
        logger.info("Enabled cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(",")}")

        // Assert
        assert enabledCipherSuites == cipherSuites
        assert enabledCipherSuites.size() == csCount
    }

    @Test
    void testShouldExtractEnabledProtocolsFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> protocols = EXPECTED_PROTOCOLS
        int protocolCount = EXPECTED_PROTOCOLS_COUNT

//        ServerConnector sc = createDefaultServerConnector()

        // List<String> dump = sc?.getDefaultConnectionFactory()?._sslContextFactory?.dump().split("\n")

        // Act
        List<String> enabledProtocols = getEnabledProtocolsFromConnectorDump(dump)
        logger.info("Enabled protocols (${enabledProtocols.size()}): ${enabledProtocols.join(",")}")

        // Assert
        assert enabledProtocols == protocols
        assert enabledProtocols.size() == protocolCount
    }

    List<String> getCipherSuitesFromConnectorDump(ServerConnector sc) {
        def dump = sc?.dump()

        return []

    }

    List<String> getEnabledCipherSuitesFromConnectorDump(List<String> dump) {
        int indexOfCipherSuites = dump.findIndexOf { it =~ "Cipher Suite" }
        int indexOfEnabledCipherSuites = dump.findIndexOf(indexOfCipherSuites) {
            it =~ /Enabled \(size=/
        }
        int enabledCSCount = (dump[indexOfEnabledCipherSuites] =~ /size=(\d+)/)[0][1] as Integer
        def enabledCS = dump[(indexOfEnabledCipherSuites + 1)..(indexOfEnabledCipherSuites + enabledCSCount)]
        enabledCS.collect { it.replaceAll(/[\s\|\-\+]+/, '') }
    }


    List<String> getEnabledProtocolsFromConnectorDump(List<String> dump) {
        int indexOfProtocols = dump.findIndexOf { it =~ "Protocol Selections" }
        int indexOfEnabledProtocols = dump.findIndexOf(indexOfProtocols) {
            it =~ /Enabled \(size=/
        }
        int enabledProtocolCount = (dump[indexOfEnabledProtocols] =~ /size=(\d+)/)[0][1] as Integer
        def enabledProtocols = dump[(indexOfEnabledProtocols + 1)..(indexOfEnabledProtocols + enabledProtocolCount)]
        enabledProtocols.collect { it.replaceAll(/[\s\|\-\+]+/, '') }
    }
}

class TestAppender extends AppenderSkeleton {
    static final List<LoggingEvent> events = new ArrayList<>()

    @Override
    protected void append(LoggingEvent e) {
        synchronized (events) {
            events.add(e)
        }
    }

    static void reset() {
        synchronized (events) {
            events.clear()
        }
    }

    @Override
    void close() {
    }

    @Override
    boolean requiresLayout() {
        return false
    }

    static List<String> getLogLines() {
        synchronized (events) {
            events.collect { LoggingEvent le -> le.getRenderedMessage() }
        }
    }
}