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
import org.apache.nifi.web.server.tls.DefaultTlsConfiguration
import org.apache.nifi.web.server.tls.TlsConfiguration
import org.apache.nifi.web.server.tls.TlsConfigurationProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.jetty.server.Connector
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
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
    final List<String> EXPECTED_DISABLED_CS = [
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            "SSL_DHE_DSS_WITH_DES_CBC_SHA",
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_DHE_RSA_WITH_DES_CBC_SHA",
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_anon_WITH_DES_CBC_SHA",
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_RSA_WITH_DES_CBC_SHA",
            "SSL_RSA_WITH_NULL_MD5",
            "SSL_RSA_WITH_NULL_SHA",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
            "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
            "TLS_DH_anon_WITH_AES_256_CBC_SHA",
            "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
            "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_NULL_SHA",
            "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_ECDSA_WITH_NULL_SHA",
            "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_RSA_WITH_NULL_SHA",
            "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_anon_WITH_NULL_SHA",
            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
            "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
            "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
            "TLS_KRB5_WITH_DES_CBC_MD5",
            "TLS_KRB5_WITH_DES_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_NULL_SHA256",
    ]
    final int EXPECTED_DISABLED_CS_COUNT = EXPECTED_DISABLED_CS.size()
    final List<String> EXPECTED_DISABLED_PROTOCOLS = ["SSLv2Hello", "SSLv3"]
    final int EXPECTED_DISABLED_PROTOCOLS_COUNT = EXPECTED_DISABLED_PROTOCOLS.size()

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
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        // Act
        jetty.configureHttpsConnector(internalServer, new HttpConfiguration(), new DefaultTlsConfiguration())
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
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        // Mock and inject the TLS configuration and provider
        final def ENABLED_CIPHER_SUITES = ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        final def ENABLED_PROTOCOLS = ["TLSv1.2"]
        TlsConfiguration mockTls = [
                getCipherSuites        : { -> ENABLED_CIPHER_SUITES },
                getCipherSuitesForJetty: { -> ENABLED_CIPHER_SUITES.toArray(new String[0]) },
                getProtocols           : { -> ENABLED_PROTOCOLS },
                getProtocolsForJetty   : { -> ENABLED_PROTOCOLS.toArray(new String[0]) }
        ] as TlsConfiguration

        // Act
        jetty.configureHttpsConnector(internalServer, new HttpConfiguration(), mockTls)
        List<Connector> connectors = Arrays.asList(internalServer.connectors)

        // Assert
        ServerConnector connector = connectors.first() as ServerConnector
        assert connector.host == "secure.host.com"

        List<String> enabledCipherSuites = getEnabledCipherSuitesFromConnectorDump(getConnectorDump(connector))
        logger.info("Enabled cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        assert enabledCipherSuites == ENABLED_CIPHER_SUITES

        List<String> enabledProtocols = getEnabledProtocolsFromConnectorDump(getConnectorDump(connector))
        logger.info("Enabled protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")
        assert enabledProtocols == ENABLED_PROTOCOLS
    }

    @Test
    void testConfigureConnectorsShouldUseTlsConfigurationProvider() {
        // Arrange
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        Server internalServer = new Server()
        JettyServer jetty = new JettyServer(internalServer, httpsProps)

        // Mock and inject the TLS configuration and provider
        final def ENABLED_CIPHER_SUITES = ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        final def ENABLED_PROTOCOLS = ["TLSv1.2"]
        TlsConfiguration mockTls = [
                getCipherSuites        : { -> ENABLED_CIPHER_SUITES },
                getCipherSuitesForJetty: { -> ENABLED_CIPHER_SUITES.toArray(new String[0]) },
                getProtocols           : { -> ENABLED_PROTOCOLS },
                getProtocolsForJetty   : { -> ENABLED_PROTOCOLS.toArray(new String[0]) }
        ] as TlsConfiguration
        TlsConfigurationProvider mockTlsProvider = [
                getConfiguration: { -> mockTls }
        ] as TlsConfigurationProvider

        jetty.tlsConfigurationProvider = mockTlsProvider

        // Act
        jetty.configureConnectors(internalServer)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Assert
        assert enabledCipherSuites == ENABLED_CIPHER_SUITES
        assert enabledProtocols == ENABLED_PROTOCOLS
    }

    // TODO: Move to integration test because of WAR loading in #configureServer()
    @Ignore("Needs to be in IT")
    @Test
    void testConstructorShouldLoadDefaultTlsConfigurationProvider() {
        // Arrange
        NiFiProperties httpsProps = new StandardNiFiProperties(rawProperties: new Properties([
                (NiFiProperties.WEB_HTTPS_PORT): "8443",
                (NiFiProperties.WEB_HTTPS_HOST): "secure.host.com",
        ]))

        final DefaultTlsConfiguration DEFAULT_TLS_CONF = new DefaultTlsConfiguration()

        // Act
        JettyServer jetty = new JettyServer(httpsProps, [] as Set<Bundle>)
        List<String> enabledCipherSuites = jetty.getEnabledTlsCipherSuites()
        logger.info("Enabled cipher suites (${enabledCipherSuites.size()}): ${enabledCipherSuites.join(", ")}")
        List<String> enabledProtocols = jetty.getEnabledTlsProtocols()
        logger.info("Enabled protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Assert
        assert enabledCipherSuites == DEFAULT_TLS_CONF.cipherSuites
        assert enabledProtocols == DEFAULT_TLS_CONF.protocols
    }

    /**
     * Returns the internal properties of the Connector > SslConnectionFactory > SslContextFactory (the cipher suites and protocols).
     *
     * @param connector the {@code ServerConnector} to examine
     * @return a List<String> of the output
     */
    private static List<String> getConnectorDump(ServerConnector connector) {
        // TODO: Now that access to the SslContextFactory is available, the #dump() parsing is unnecessary
        (connector.getDefaultConnectionFactory() as SslConnectionFactory).getSslContextFactory().dump().split("\n")
    }

    @Test
    void testShouldExtractEnabledCipherSuitesFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> cipherSuites = EXPECTED_CS
        int csCount = EXPECTED_CS_COUNT

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

        // Act
        List<String> enabledProtocols = getEnabledProtocolsFromConnectorDump(dump)
        logger.info("Enabled protocols (${enabledProtocols.size()}): ${enabledProtocols.join(", ")}")

        // Assert
        assert enabledProtocols == protocols
        assert enabledProtocols.size() == protocolCount
    }

    @Test
    void testShouldExtractDisabledCipherSuitesFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> cipherSuites = EXPECTED_DISABLED_CS
        int csCount = EXPECTED_DISABLED_CS_COUNT

        // Act
        List<String> disabledCipherSuites = getDisabledCipherSuitesFromConnectorDump(dump)
        logger.info("Disabled cipher suites (${disabledCipherSuites.size()}): ${disabledCipherSuites.join(", ")}")

        // Assert
        assert disabledCipherSuites == cipherSuites
        assert disabledCipherSuites.size() == csCount
    }

    @Test
    void testShouldExtractDisabledProtocolsFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> protocols = EXPECTED_DISABLED_PROTOCOLS
        int protocolCount = EXPECTED_DISABLED_PROTOCOLS_COUNT

        // Act
        List<String> disabledProtocols = getDisabledProtocolsFromConnectorDump(dump)
        logger.info("Disabled protocols (${disabledProtocols.size()}): ${disabledProtocols.join(", ")}")

        // Assert
        assert disabledProtocols == protocols
        assert disabledProtocols.size() == protocolCount
    }

    @Test
    void testShouldExtractDisabledCipherSuitesWithReasonFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> cipherSuites = EXPECTED_DISABLED_CS
        int csCount = EXPECTED_DISABLED_CS_COUNT

        // Act
        Map<String, String> disabledCipherSuites = getDisabledCipherSuitesWithReasonFromConnectorDump(dump)
        logger.info("Disabled cipher suites (${disabledCipherSuites.size()}): ${disabledCipherSuites.entrySet() join(", ")}")

        // Assert
        assert disabledCipherSuites.keySet() == cipherSuites as Set
        assert disabledCipherSuites.size() == csCount
    }

    @Test
    void testShouldExtractDisabledProtocolsWithReasonFromConnectorDump() {
        // Arrange
        List<String> dump = EXAMPLE_SC_DUMP.split("\n")
        List<String> protocols = EXPECTED_DISABLED_PROTOCOLS
        int protocolCount = EXPECTED_DISABLED_PROTOCOLS_COUNT

        // Act
        Map<String, String> disabledProtocols = getDisabledProtocolsWithReasonFromConnectorDump(dump)
        logger.info("Disabled protocols (${disabledProtocols.size()}): ${disabledProtocols.entrySet() join(", ")}")

        // Assert
        assert disabledProtocols.keySet() == protocols as Set
        assert disabledProtocols.size() == protocolCount
    }

    List<String> getEnabledCipherSuitesFromConnectorDump(List<String> dump) {
        getEnabledElements(dump, "Cipher Suite")
    }

    List<String> getEnabledProtocolsFromConnectorDump(List<String> dump) {
        getEnabledElements(dump, "Protocol Selections")
    }

    List<String> getDisabledCipherSuitesFromConnectorDump(List<String> dump) {
        new ArrayList<>(getDisabledElements(dump, "Cipher Suite").keySet())
    }

    List<String> getDisabledProtocolsFromConnectorDump(List<String> dump) {
        new ArrayList<>(getDisabledElements(dump, "Protocol Selections").keySet())
    }

    Map<String, String> getDisabledCipherSuitesWithReasonFromConnectorDump(List<String> dump) {
        getDisabledElements(dump, "Cipher Suite")
    }

    Map<String, String> getDisabledProtocolsWithReasonFromConnectorDump(List<String> dump) {
        getDisabledElements(dump, "Protocol Selections")
    }

    List<String> getEnabledElements(List<String> dump, String elementName) {
        getElements(dump, elementName, true)
    }

    /**
     * Returns a map of the disabled element and the "reason" it is disabled.
     *
     * Example:
     *
     * {@code ["SSLv3": "JreDisabled:java.security, ConfigExcluded:'SSLv3'"]}
     * @param dump the output of {@code object.dump ( ) .split ( " \ n " )}
     * @param elementName the elements requested (i.e. "Cipher Suite Selections" or "Protocol Selections")
     * @return the map of requested elements (stripped of the hierarchy character indicators) and their reasons
     */
    Map<String, String> getDisabledElements(List<String> dump, String elementName) {
        def strippedElements = getElements(dump, elementName, false)
        def splitElements = strippedElements.collectEntries {
            def e = it.split(" - ")
            [(e[0]): e[1]]
        }
        splitElements
    }

    /**
     * Returns a list of the {@code elementName}s that are in the specified state ({@code Enabled} or {@code Disabled}).
     *
     * @param dump the output of {@code object.dump ( ) .split ( " \ n " )}
     * @param elementName the elements requested (i.e. "Cipher Suite Selections" or "Protocol Selections")
     * @param enabled true for enabled elements; false for disabled
     * @return the list of requested elements (stripped of the hierarchy character indicators)
     */
    List<String> getElements(List<String> dump, String elementName, boolean enabled) {
        String state = enabled ? "Enabled" : "Disabled"
        int indexOfElements = dump.findIndexOf { it =~ elementName }
        int indexOfSelectedElements = dump.findIndexOf(indexOfElements) {
            it =~ /${state} \(size=/
        }
        int selectedElementCount = (dump[indexOfSelectedElements] =~ /size=(\d+)/)[0][1] as Integer
        def selectedElements = dump[(indexOfSelectedElements + 1)..(indexOfSelectedElements + selectedElementCount)]
        selectedElements.collect { it.replaceAll(/^[\s\|\-\+]+/, '') }
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