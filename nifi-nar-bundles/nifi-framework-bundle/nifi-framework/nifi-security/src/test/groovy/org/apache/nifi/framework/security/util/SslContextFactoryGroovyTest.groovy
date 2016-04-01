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
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE
import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE_PASSWD
import static org.apache.nifi.util.NiFiProperties.SECURITY_KEYSTORE_TYPE
import static org.apache.nifi.util.NiFiProperties.SECURITY_NEED_CLIENT_AUTH
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE_PASSWD
import static org.apache.nifi.util.NiFiProperties.SECURITY_TRUSTSTORE_TYPE

@RunWith(JUnit4.class)
class SslContextFactoryGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(SslContextFactoryGroovyTest.class)

    private static Map<String, List<String>> MOZILLA_CIPHER_SUITES
    private static List<String> CUSTOM_NIFI_CIPHER_SUITES

    private static final String MZ_OLD = "old"
    private static final String MZ_INTERMEDIATE = "intermediate"
    private static final String MZ_MODERN = "modern"

    private static final String MOZILLA_CURRENT_TLS_URL = "https://statics.tls.security.mozilla.org/server-side-tls-conf.json"

    private static NiFiProperties DEFAULT_PROPS
    private static NiFiProperties MUTUAL_AUTH_PROPS

    private static final String KEYSTORE_PASSWORD = "localtest"
    private static final String TRUSTSTORE_PASSWORD = "localtest"

    private SslContextFactory sslContextFactory

    @BeforeClass
    static void setUpOnce() {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

//        retrieveTLSConfigurationsFromMozilla()
        setUpProperties()
    }

    private static void setUpProperties() {
        final File keystoreFile = new File(SslContextFactoryTest.class.getResource("/localhost-ks.jks").toURI());
        final File truststoreFile = new File(SslContextFactoryTest.class.getResource("/localhost-ts.jks").toURI());

        def propertiesMap = [
                (SECURITY_KEYSTORE)        : keystoreFile.getAbsolutePath(),
                (SECURITY_KEYSTORE_TYPE)   : KeystoreType.JKS as String,
                (SECURITY_KEYSTORE_PASSWD) : KEYSTORE_PASSWORD,
                (SECURITY_NEED_CLIENT_AUTH): false
        ]

        DEFAULT_PROPS = mockProperties(propertiesMap)

        MUTUAL_AUTH_PROPS = propertiesMap + [
                (SECURITY_TRUSTSTORE)       : truststoreFile.getAbsolutePath(),
                (SECURITY_TRUSTSTORE_TYPE)  : KeystoreType.JKS as String,
                (SECURITY_TRUSTSTORE_PASSWD): TRUSTSTORE_PASSWORD,
                (SECURITY_NEED_CLIENT_AUTH) : true
        ] as NiFiProperties
    }

    private static NiFiProperties mockProperties(Map props) {
//        def stubbedProperties = new StubFor(NiFiProperties)
//        stubbedProperties.demand.with {
//            getProperty { String propName ->
//                if (props.containsKey(propName)) {
//                    return props.get(propName)
//                } else {
//                    return ""
//                }
//            }
//            methodMissing { String method, def args ->
//                    logger.methodMissing("Tried to call missing NiFiProperties.${method}(${args})")
//                    return null
//            }
//        }
//
//        return stubbedProperties

        NiFiProperties nfp = new NiFiProperties(props)
        nfp.getMetaClass().getProperty = { String propName ->
            if (props.containsKey(propName)) {
                props.get(propName)
            } else {
                ""
            }
        }
        nfp.getMetaClass().getNeedClientAuth = { ->
            props.get(SECURITY_NEED_CLIENT_AUTH) ?: "true"
        }

//        nfp.getMetaClass().invokeMethod = { String methodName, def args ->
//            if (methodName == "getMetaClass") {
//                return getMetaClass()
//            }
//            logger.invoked("Tried to call NiFiProperties.${methodName}(${args})")
//            def m = delegate.getMetaClass().getMetaMethod(methodName, *args)
//            if (m) {
////                delegate."$methodName"(*args)
////                logger.debug("Type of delegate: ${delegate.getClass().getCanonicalName()}")
//                m.invoke(delegate , *args)
//            } else {
//                delegate.getMetaClass().invokeMissingMethod(delegate, methodName, args)
//            }
////            m ? m.invoke(delegate, *args) : delegate.getMetaClass().invokeMissingMethod(delegate, methodName, args)
//        }

        nfp.getMetaClass().methodMissing = { String method, def args ->
            logger.methodMissing("Tried to call missing NiFiProperties.${method}(${args})")
            return null
        }
        nfp.getMetaClass().toString = { ->
            delegate.dump()
        }

//        MockNiFiProperties nfp = [getProperty: { String propName -> "${propName}_value"}] as MockNiFiProperties
        nfp
    }

    private static void retrieveTLSConfigurationsFromMozilla() {
        MOZILLA_CIPHER_SUITES = [:]

        def mozillaTlsJson = MOZILLA_CURRENT_TLS_URL.toURL().text
        logger.info("Retrieved from Mozilla: ${mozillaTlsJson}")
        JsonSlurper slurper = new JsonSlurper()
        def json = slurper.parseText(mozillaTlsJson)
        assert json.configurations.modern
        MOZILLA_CIPHER_SUITES[MZ_MODERN] = json.configurations.modern.ciphersuites

        assert json.configurations.intermediate
        MOZILLA_CIPHER_SUITES[MZ_INTERMEDIATE] = json.configurations.intermediate.ciphersuites

        assert json.configurations.old
        MOZILLA_CIPHER_SUITES[MZ_OLD] = json.configurations.old.ciphersuites
    }

    @Before
    void setUp() {
        super.setUp()

    }

    @After
    void tearDown() {

    }

    @Test
    void testDefaultCreateSslContextCipherSuitesShouldMeetIntermediateThreshold() {
        // Arrange
        sslContextFactory = new SslContextFactory()
        logger.settings(DEFAULT_PROPS)

        logger.sanity("Expected keystore path: ${DEFAULT_PROPS.getProperty(SECURITY_KEYSTORE)}")
        logger.sanity("Expected keystore type: ${DEFAULT_PROPS.getProperty(SECURITY_KEYSTORE_TYPE)}")
        logger.sanity("Expected keystore password: ${DEFAULT_PROPS.getProperty(SECURITY_KEYSTORE_PASSWD)}")
        logger.sanity("Expected need client auth: ${DEFAULT_PROPS.getProperty(SECURITY_NEED_CLIENT_AUTH)}")

        // Act
        def sslContext = sslContextFactory.createSslContext(DEFAULT_PROPS)
        logger.info("SSL Context: ${sslContext?.dump()}")

        // Assert
        assert sslContext

    }
}

//public class MockNiFiProperties extends NiFiProperties {
//    public MockNiFiProperties(Map props) {
//        super(props)
//    }
//
//    @Override
//    public String toString() {
//        dump()
//    }
//}