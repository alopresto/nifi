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
package org.apache.nifi.security.util


import org.apache.nifi.util.NiFiProperties
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import java.security.Security

@RunWith(JUnit4.class)
class SslContextFactoryTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(SslContextFactoryTest.class)

    private static final String KEYSTORE_PATH = "src/test/resources/TlsConfigurationKeystore.jks"
    private static final String KEYSTORE_PASSWORD = "keystorepassword"
    private static final String KEY_PASSWORD = "keypassword"
    private static final KeystoreType KEYSTORE_TYPE = KeystoreType.JKS

    private static final String TRUSTSTORE_PATH = "src/test/resources/TlsConfigurationTruststore.jks"
    private static final String TRUSTSTORE_PASSWORD = "truststorepassword"
    private static final KeystoreType TRUSTSTORE_TYPE = KeystoreType.JKS

    private static final String PROTOCOL = CertificateUtils.CURRENT_TLS_PROTOCOL_VERSION

    private static final Map<String, String> DEFAULT_PROPS = [
            (NiFiProperties.SECURITY_KEYSTORE)         : KEYSTORE_PATH,
            (NiFiProperties.SECURITY_KEYSTORE_PASSWD)  : KEYSTORE_PASSWORD,
            (NiFiProperties.SECURITY_KEY_PASSWD)       : KEY_PASSWORD,
            (NiFiProperties.SECURITY_KEYSTORE_TYPE)    : KEYSTORE_TYPE.getType(),
            (NiFiProperties.SECURITY_TRUSTSTORE)       : TRUSTSTORE_PATH,
            (NiFiProperties.SECURITY_TRUSTSTORE_PASSWD): TRUSTSTORE_PASSWORD,
            (NiFiProperties.SECURITY_TRUSTSTORE_TYPE)  : TRUSTSTORE_TYPE.getType(),
    ]

    private NiFiProperties mockNiFiProperties = NiFiProperties.createBasicNiFiProperties(null, DEFAULT_PROPS)

    private TlsConfiguration tlsConfiguration

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() {
        tlsConfiguration = new TlsConfiguration(KEYSTORE_PATH, KEYSTORE_PASSWORD, KEY_PASSWORD, KEYSTORE_TYPE, TRUSTSTORE_PATH, TRUSTSTORE_PASSWORD, TRUSTSTORE_TYPE)
    }

    @After
    void tearDown() {

    }

    @Test
    void testShouldCreateSslContextFromTlsConfiguration() {
        // Arrange
        logger.info("Creating SSL Context from TLS Configuration: ${tlsConfiguration}")

        // Act
        SSLContext sslContext = SslContextFactory.createSslContext(tlsConfiguration, SslContextFactory.ClientAuth.NONE)
        logger.info("Created SSL Context: ${KeyStoreUtils.sslContextToString(sslContext)}")

        // Assert
        assert sslContext.protocol == tlsConfiguration.protocol

        def defaultSSLParameters = sslContext.defaultSSLParameters
        logger.info("Default SSL Parameters: ${KeyStoreUtils.sslParametersToString(defaultSSLParameters)}" as String)
        assert defaultSSLParameters.getProtocols() == ["TLSv1.2", "TLSv1.1", "TLSv1"] as String[]
        assert !defaultSSLParameters.needClientAuth
        assert !defaultSSLParameters.wantClientAuth

        // Check a socket created from this context
        SSLServerSocket sslSocket = sslContext.serverSocketFactory.createServerSocket() as SSLServerSocket
        logger.info("Created SSL (server) socket: ${sslSocket}")
        assert sslSocket.enabledProtocols.contains("TLSv1.2")

        // Override the SSL parameters protocol version
        SSLServerSocket customSslSocket = sslContext.serverSocketFactory.createServerSocket() as SSLServerSocket
        def customParameters = customSslSocket.getSSLParameters()
        customParameters.setProtocols(["TLSv1.2"] as String[])
        customSslSocket.setSSLParameters(customParameters)
        assert customSslSocket.enabledProtocols == ["TLSv1.2"] as String[]
    }
}