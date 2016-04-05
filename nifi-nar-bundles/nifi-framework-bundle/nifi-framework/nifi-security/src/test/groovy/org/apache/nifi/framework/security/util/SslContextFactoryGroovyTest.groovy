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
package org.apache.nifi.framework.security.util

import groovy.json.JsonSlurper
import org.apache.nifi.security.util.KeystoreType
import org.apache.nifi.util.NiFiProperties
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.ssl.SSLContext
import java.security.Security

import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE
import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE_PASSWD
import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE_TYPE
import static org.apache.nifi.util.NiFiProperties.SECURITY_NEED_CLIENT_AUTH
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE_PASSWD
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE_TYPE
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

@RunWith(JUnit4.class)
class SslContextFactoryGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(SslContextFactoryGroovyTest.class)

    private static def MOZILLA_CONFIGURATIONS
    private static Map<String, List<String>> MOZILLA_CIPHER_SUITES
    private static List<String> CUSTOM_NIFI_CIPHER_SUITES

    private static final String MZ_OLD = "old"
    private static final String MZ_INTERMEDIATE = "intermediate"
    private static final String MZ_MODERN = "modern"

    private static final String MOZILLA_CURRENT_TLS_URL = "https://statics.tls.security.mozilla.org/server-side-tls-conf.json"

    private static Map propertiesMap
    private static NiFiProperties DEFAULT_PROPS
    private static NiFiProperties MUTUAL_AUTH_PROPS

    private static final String KEYSTORE_PASSWORD = "localtest"
    private static final String TRUSTSTORE_PASSWORD = "localtest"

    private SslContextFactory sslContextFactory
    private static final Map LEGACY_NIFI_060_CONFIGURATION = [
            tls_versions    : ["SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"],
            ciphersuites    : legacyNiFi060CipherSuites(),
            ciphersuiteorder: false
    ]

    private static List<String> legacyNiFi060CipherSuites() {
        ["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
         "TLS_RSA_WITH_AES_256_CBC_SHA256",
         "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
         "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
         "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
         "TLS_RSA_WITH_AES_256_CBC_SHA",
         "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
         "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
         "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
         "TLS_RSA_WITH_AES_128_CBC_SHA256",
         "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
         "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
         "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
         "TLS_RSA_WITH_AES_128_CBC_SHA",
         "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
         "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
         "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
         "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
         "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
         "TLS_RSA_WITH_AES_256_GCM_SHA384",
         "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
         "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
         "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
         "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "TLS_RSA_WITH_AES_128_GCM_SHA256",
         "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
         "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
         "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
         "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
         "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
         "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
         "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
         "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
         "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
         "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
         "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
         "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
         "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
         "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
         "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
         "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
         "TLS_DH_anon_WITH_AES_256_CBC_SHA",
         "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
         "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
         "TLS_DH_anon_WITH_AES_128_CBC_SHA",
         "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
         "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
         "SSL_RSA_WITH_DES_CBC_SHA",
         "SSL_DHE_RSA_WITH_DES_CBC_SHA",
         "SSL_DHE_DSS_WITH_DES_CBC_SHA",
         "SSL_DH_anon_WITH_DES_CBC_SHA",
         "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
         "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
         "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
         "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
         "TLS_RSA_WITH_NULL_SHA256",
         "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
         "TLS_ECDHE_RSA_WITH_NULL_SHA",
         "SSL_RSA_WITH_NULL_SHA",
         "TLS_ECDH_ECDSA_WITH_NULL_SHA",
         "TLS_ECDH_RSA_WITH_NULL_SHA",
         "TLS_ECDH_anon_WITH_NULL_SHA",
         "SSL_RSA_WITH_NULL_MD5",
         "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
         "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
         "TLS_KRB5_WITH_DES_CBC_SHA",
         "TLS_KRB5_WITH_DES_CBC_MD5",
         "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
         "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]
    }

    @BeforeClass
    static void setUpOnce() {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        MOZILLA_CONFIGURATIONS = retrieveTLSConfigurationsFromMozilla().configurations
        MOZILLA_CIPHER_SUITES = parseCipherSuitesFromConfigurations(MOZILLA_CONFIGURATIONS)
        setUpProperties()
    }

    private static void setUpProperties() {
        final File keystoreFile = new File(SslContextFactoryTest.class.getResource("/localhost-ks.jks").toURI());
        final File truststoreFile = new File(SslContextFactoryTest.class.getResource("/localhost-ts.jks").toURI());

        propertiesMap = [
                (SECURITY_KEYSTORE)        : keystoreFile.getAbsolutePath(),
                (SECURITY_KEYSTORE_TYPE)   : KeystoreType.JKS as String,
                (SECURITY_KEYSTORE_PASSWD) : KEYSTORE_PASSWORD,
                (SECURITY_NEED_CLIENT_AUTH): "false"
        ]

        DEFAULT_PROPS = mockProperties(propertiesMap)

        MUTUAL_AUTH_PROPS = mockProperties(propertiesMap + [
                (SECURITY_TRUSTSTORE)       : truststoreFile.getAbsolutePath(),
                (SECURITY_TRUSTSTORE_TYPE)  : KeystoreType.JKS as String,
                (SECURITY_TRUSTSTORE_PASSWD): TRUSTSTORE_PASSWORD,
                (SECURITY_NEED_CLIENT_AUTH) : "true"
        ])
    }

    private static NiFiProperties mockProperties(Map props) {
        def nfp = mock(NiFiProperties.class) as NiFiProperties
        props.each { String k, String v ->
            when(nfp.getProperty(k)).thenReturn(v)
        }

        when(nfp.getNeedClientAuth()).thenReturn(props.get(SECURITY_NEED_CLIENT_AUTH) != "false")

        nfp
    }

    private static def retrieveTLSConfigurationsFromMozilla() {
        def mozillaTlsJson = MOZILLA_CURRENT_TLS_URL.toURL().text
        logger.debug("Retrieved from Mozilla: ${mozillaTlsJson}")
        JsonSlurper slurper = new JsonSlurper()
        slurper.parseText(mozillaTlsJson)
    }

    public static void parseCipherSuitesFromConfigurations(jsonConfigurations) {
        def configurations = [:]

        assert jsonConfigurations.modern
        configurations[MZ_MODERN] = jsonConfigurations.modern.ciphersuites

        assert jsonConfigurations.intermediate
        configurations[MZ_INTERMEDIATE] = jsonConfigurations.intermediate.ciphersuites

        assert jsonConfigurations.old
        configurations[MZ_OLD] = jsonConfigurations.old.ciphersuites

        configurations
    }

    private static boolean sslContextMeetsConfiguration(SSLContext context, def configuration) {
        // Ensure an SSLContext exists
        def params = context?.supportedSSLParameters
        assert params

        // Parse the supported protocols and cipher suites from the SSLContext
        List<String> protocols = params.protocols as List
        logger.context("Protocols: ${protocols}")
        List<String> cipherSuites = params.cipherSuites as List
        logger.context("Cipher suites: ${cipherSuites}")
        boolean cipherSuiteOrder = params.getUseCipherSuitesOrder()
        logger.context("Cipher suite order enforced: ${cipherSuiteOrder}")

        // Parse the expected protocols and cipher suites from the configuration
        List<String> configProtocols = configuration.tls_versions as List
        logger.config("Protocols: ${configProtocols}")
        List<String> configCipherSuites = configuration.ciphersuites as List
        logger.config("Cipher suites: ${configCipherSuites}")
        boolean configCipherSuiteOrder = configuration.ciphersuiteorder != null ? configuration.ciphersuiteorder : true
        logger.config("Cipher suite order enforced: ${configCipherSuiteOrder}")

        assert protocols as Set == configProtocols as Set, "Protocols do not match"
        assert cipherSuites as Set == configuration.ciphersuites as Set, "Cipher suites do not match"
        assert cipherSuiteOrder == configCipherSuiteOrder, "Cipher suite order enforcement does not match"

        true
    }

    @Before
    void setUp() {
        super.setUp()

    }

    @After
    void tearDown() {

    }

    @Test
    void testDefaultCreateSslContextShouldMeetLegacyNiFiConfiguration() {
        // Arrange
        sslContextFactory = new SslContextFactory()

        // Act
        def sslContext = sslContextFactory.createSslContext(DEFAULT_PROPS)
        logger.info("SSL Context: ${sslContext?.dump()?.split(/, /)?.join("\n")}")

        // Assert
        assert sslContextMeetsConfiguration(sslContext, LEGACY_NIFI_060_CONFIGURATION)
    }

    @Ignore("Default NiFi does not yet meet Mozilla intermediate")
    @Test
    void testDefaultCreateSslContextShouldMeetMozillaIntermediateConfiguration() {
        // Arrange
        sslContextFactory = new SslContextFactory()

        // Act
        def sslContext = sslContextFactory.createSslContext(DEFAULT_PROPS)
        logger.info("SSL Context: ${sslContext?.dump()?.split(/, /)?.join("\n")}")

        // Assert
        assert sslContextMeetsConfiguration(sslContext, MOZILLA_CONFIGURATIONS.intermediate)
    }

    @Ignore("Not yet implemented")
    @Test
    void testCreateIntermediateSslContextShouldMeetMozillaIntermediateConfiguration() {
        // Arrange
        sslContextFactory = new SslContextFactory()

        // Act
        def sslContext = sslContextFactory.createSslContext(SslContextFactory.TLSConfiguration.INTERMEDIATE, DEFAULT_PROPS)
        logger.info("SSL Context: ${sslContext?.dump()?.split(/, /)?.join("\n")}")

        // Assert
        assert sslContextMeetsConfiguration(sslContext, MOZILLA_CONFIGURATIONS.intermediate)
    }

    /**
     * Regression test to ensure proper validation still occurs
     */
    @Test
    void testCreateSslContextShouldRequireKeystoreProperties() {
        // Arrange
        sslContextFactory = new SslContextFactory()

        NiFiProperties emptyProperties = mockProperties([:])

        // Act

        /* The default method provides "false" as the strict parameter. If strict mode is false, properties missing the keystore properties result in a null return value */
        def emptyContext = sslContextFactory.createSslContext(emptyProperties)
        logger.info("Empty context: ${emptyContext}")
        def emptyContextExplicit = sslContextFactory.createSslContext(emptyProperties, false)
        logger.info("Empty context (explicit): ${emptyContextExplicit}")

        // If strict mode is true, missing keystore properties throw an exception
        def msg = shouldFail(SslContextCreationException) {
            def sslContext = sslContextFactory.createSslContext(emptyProperties, true)
        }
        logger.expected(msg)

        // Assert
        assert emptyContext == null
        assert emptyContextExplicit == null
        assert msg =~ "SSL context cannot be created because keystore properties have not been configured."
    }

    /**
     * Regression test to ensure proper validation still occurs
     */
    @Test
    void testCreateSslContextWithClientAuthShouldRequireTruststoreProperties() {
        // Arrange
        sslContextFactory = new SslContextFactory()

        NiFiProperties emptyTruststoreProperties = mockProperties(propertiesMap + [(SECURITY_NEED_CLIENT_AUTH):"true"])

        // Act
        def msg = shouldFail(SslContextCreationException) {
            def sslContext = sslContextFactory.createSslContext(emptyTruststoreProperties)
        }
        logger.expected(msg)

        // Assert
        assert msg =~ "Need client auth is set to 'true', but no truststore properties are configured."
    }
}