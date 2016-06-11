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
package org.apache.nifi.properties

import org.apache.nifi.util.NiFiProperties
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class ProtectedNiFiPropertiesGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(ProtectedNiFiPropertiesGroovyTest.class)

    final def DEFAULT_SENSITIVE_PROPERTIES = [
            "nifi.sensitive.props.key",
            "nifi.security.keystorePasswd",
            "nifi.security.keyPasswd",
            "nifi.security.truststorePasswd"
    ]

    final def COMMON_ADDITIONAL_SENSITIVE_PROPERTIES = [
            "nifi.sensitive.props.algorithm",
            "nifi.kerberos.service.principal",
            "nifi.kerberos.krb5.file",
            "nifi.kerberos.keytab.location"
    ]

    private static final String DEFAULT_KEY = "0123456789ABCDEFFEDCBA9876543210" * 2

    private static String originalPropertiesPath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    public void setUp() throws Exception {
        NiFiProperties.@protectionKey = DEFAULT_KEY
    }

    @After
    public void tearDown() throws Exception {
        NiFiProperties.@instance = null
    }

    @AfterClass
    public static void tearDownOnce() {
        if (originalPropertiesPath) {
            System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, originalPropertiesPath)
        }
    }

    private static NiFiProperties loadFromFile(String propertiesFilePath) {
        String filePath;
        try {
            filePath = ProtectedNiFiPropertiesGroovyTest.class.getResource(propertiesFilePath).toURI().getPath();
        } catch (URISyntaxException ex) {
            throw new RuntimeException("Cannot load properties file due to "
                    + ex.getLocalizedMessage(), ex);
        }

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, filePath);

        NiFiProperties properties = NiFiProperties.getInstance();
        // Clear static provider cache & factory
        properties.@localProviderCache = [:]
        properties.@sensitivePropertyProviderFactory = new SensitivePropertyProviderFactory()

        // clear out existing properties
        for (String prop : properties.stringPropertyNames()) {
            properties.remove(prop);
        }

        InputStream inStream = null;
        try {
            inStream = new BufferedInputStream(new FileInputStream(filePath));
            properties.load(inStream);
        } catch (final Exception ex) {
            throw new RuntimeException("Cannot load properties file due to "
                    + ex.getLocalizedMessage(), ex);
        } finally {
            if (null != inStream) {
                try {
                    inStream.close();
                } catch (Exception ex) {
                    /**
                     * do nothing *
                     */
                }
            }
        }

        if (properties.hasProtectedKeys()) {
            properties.initializeSensitivePropertyProviderFactory()
        }

        return properties;
    }

    @Test
    public void testShouldDetectIfPropertyIsSensitive() throws Exception {
        // Arrange
        final String INSENSITIVE_PROPERTY_KEY = "nifi.ui.banner.text"
        final String SENSITIVE_PROPERTY_KEY = "nifi.security.keystorePasswd"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")

        // Act
        boolean bannerIsSensitive = properties.isPropertySensitive(INSENSITIVE_PROPERTY_KEY)
        logger.info("${INSENSITIVE_PROPERTY_KEY} is ${bannerIsSensitive ? "SENSITIVE" : "NOT SENSITIVE"}")
        boolean passwordIsSensitive = properties.isPropertySensitive(SENSITIVE_PROPERTY_KEY)
        logger.info("${SENSITIVE_PROPERTY_KEY} is ${passwordIsSensitive ? "SENSITIVE" : "NOT SENSITIVE"}")

        // Assert
        assert !bannerIsSensitive
        assert passwordIsSensitive
    }

    @Test
    public void testShouldGetDefaultSensitiveProperties() throws Exception {
        // Arrange
        logger.expected("${DEFAULT_SENSITIVE_PROPERTIES.size()} default sensitive properties: ${DEFAULT_SENSITIVE_PROPERTIES.join(", ")}")
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")

        // Act
        List defaultSensitiveProperties = properties.getSensitivePropertyKeys()
        logger.info("${defaultSensitiveProperties.size()} default sensitive properties: ${defaultSensitiveProperties.join(", ")}")

        // Assert
        assert defaultSensitiveProperties.size() == DEFAULT_SENSITIVE_PROPERTIES.size()
        assert defaultSensitiveProperties.containsAll(DEFAULT_SENSITIVE_PROPERTIES)
    }

    @Test
    public void testShouldGetAdditionalSensitiveProperties() throws Exception {
        // Arrange
        def completeSensitiveProperties = DEFAULT_SENSITIVE_PROPERTIES + ["nifi.ui.banner.text", "nifi.version"]
        logger.expected("${completeSensitiveProperties.size()} total sensitive properties: ${completeSensitiveProperties.join(", ")}")
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_additional_sensitive_keys.properties")

        // Act
        List retrievedSensitiveProperties = properties.getSensitivePropertyKeys()
        logger.info("${retrievedSensitiveProperties.size()} retrieved sensitive properties: ${retrievedSensitiveProperties.join(", ")}")

        // Assert
        assert retrievedSensitiveProperties.size() == completeSensitiveProperties.size()
        assert retrievedSensitiveProperties.containsAll(completeSensitiveProperties)
    }

    // TODO: Add negative tests (fuzz additional.keys property, etc.)

    @Test
    public void testGetAdditionalSensitivePropertiesShouldNotIncludeSelf() throws Exception {
        // Arrange
        def completeSensitiveProperties = DEFAULT_SENSITIVE_PROPERTIES + ["nifi.ui.banner.text", "nifi.version"]
        logger.expected("${completeSensitiveProperties.size()} total sensitive properties: ${completeSensitiveProperties.join(", ")}")
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_additional_sensitive_keys.properties")

        // Act
        List retrievedSensitiveProperties = properties.getSensitivePropertyKeys()
        logger.info("${retrievedSensitiveProperties.size()} retrieved sensitive properties: ${retrievedSensitiveProperties.join(", ")}")

        // Assert
        assert retrievedSensitiveProperties.size() == completeSensitiveProperties.size()
        assert retrievedSensitiveProperties.containsAll(completeSensitiveProperties)
    }

    /**
     * In the default (no protection enabled) scenario, a call to retrieve a sensitive property should return the raw value transparently.
     * @throws Exception
     */
    @Test
    public void testShouldGetUnprotectedValueOfSensitiveProperty() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"
        final String EXPECTED_KEYSTORE_PASSWORD = "thisIsABadKeystorePassword"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_unprotected.properties")

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")

        // Assert
        assert retrievedKeystorePassword == EXPECTED_KEYSTORE_PASSWORD
        assert isSensitive
        assert !isProtected
    }

    /**
     * In the default (no protection enabled) scenario, a call to retrieve a sensitive property (which is empty) should return the raw value transparently.
     * @throws Exception
     */
    @Test
    public void testShouldGetEmptyUnprotectedValueOfSensitiveProperty() throws Exception {
        // Arrange
        final String TRUSTSTORE_PASSWORD_KEY = "nifi.security.truststorePasswd"
        final String EXPECTED_TRUSTSTORE_PASSWORD = ""

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_unprotected.properties")

        boolean isSensitive = properties.isPropertySensitive(TRUSTSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(TRUSTSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedTruststorePassword = properties.getProperty(TRUSTSTORE_PASSWORD_KEY)
        logger.info("${TRUSTSTORE_PASSWORD_KEY}: ${retrievedTruststorePassword}")

        // Assert
        assert retrievedTruststorePassword == EXPECTED_TRUSTSTORE_PASSWORD
        assert isSensitive
        assert !isProtected
    }

    /**
     * In the protection enabled scenario, a call to retrieve a sensitive property should return the raw value transparently.
     * @throws Exception
     */
    @Test
    public void testShouldGetUnprotectedValueOfSensitivePropertyWhenProtected() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"
        final String EXPECTED_KEYSTORE_PASSWORD = "thisIsABadKeystorePassword"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")

        // Assert
        assert retrievedKeystorePassword == EXPECTED_KEYSTORE_PASSWORD
        assert isSensitive
        assert isProtected
    }

    /**
     * In the protection enabled scenario, a call to retrieve a sensitive property should handle if the property is protected with an unknown protection scheme.
     * @throws Exception
     */
    @Test
    public void testGetValueOfSensitivePropertyShouldHandleUnknownProtectionScheme() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"

        // Raw properties
        Properties rawProperties = new Properties()
        rawProperties.load(new File("src/test/resources/NiFiProperties/conf/nifi_with_sensitive_properties_protected_unknown.properties").newInputStream())
        final String RAW_KEYSTORE_PASSWORD = rawProperties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("Raw value for ${KEYSTORE_PASSWORD_KEY}: ${RAW_KEYSTORE_PASSWORD}")

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_unknown.properties")

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)

        // While the value is "protected", the scheme is not registered, so treat it as raw
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")

        // Assert
        assert retrievedKeystorePassword == RAW_KEYSTORE_PASSWORD
        assert isSensitive
        assert isProtected
    }

    /**
     * In the protection enabled scenario, a call to retrieve a sensitive property should handle if the property is unable to be unprotected due to a malformed value.
     * @throws Exception
     */
    @Test
    public void testGetValueOfSensitivePropertyShouldHandleMalformedValue() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"

        // Raw properties
        Properties rawProperties = new Properties()
        rawProperties.load(new File("src/test/resources/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes_malformed.properties").newInputStream())
        final String RAW_KEYSTORE_PASSWORD = rawProperties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("Raw value for ${KEYSTORE_PASSWORD_KEY}: ${RAW_KEYSTORE_PASSWORD}")

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes_malformed.properties")

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        def msg = shouldFail(SensitivePropertyProtectionException) {
            String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY)
            logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")
        }
        logger.expected(msg)

        // Assert
        assert msg =~ "Error unprotecting value for ${KEYSTORE_PASSWORD_KEY}"
        assert isSensitive
        assert isProtected
    }

    /**
     * In the default (no protection enabled) scenario, a call to retrieve a sensitive property (which is empty) should return the raw value transparently.
     * @throws Exception
     */
    @Test
    public void testShouldGetEmptyUnprotectedValueOfSensitivePropertyWithDefault() throws Exception {
        // Arrange
        final String TRUSTSTORE_PASSWORD_KEY = "nifi.security.truststorePasswd"
        final String EXPECTED_TRUSTSTORE_PASSWORD = ""
        final String DEFAULT_VALUE = "defaultValue"

        // Raw properties
        Properties rawProperties = new Properties()
        rawProperties.load(new File("src/test/resources/NiFiProperties/conf/nifi_with_sensitive_properties_unprotected.properties").newInputStream())
        final String RAW_TRUSTSTORE_PASSWORD = rawProperties.getProperty(TRUSTSTORE_PASSWORD_KEY)
        logger.info("Raw value for ${TRUSTSTORE_PASSWORD_KEY}: ${RAW_TRUSTSTORE_PASSWORD}")
        assert RAW_TRUSTSTORE_PASSWORD == EXPECTED_TRUSTSTORE_PASSWORD

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_unprotected.properties")

        boolean isSensitive = properties.isPropertySensitive(TRUSTSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(TRUSTSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedTruststorePassword = properties.getProperty(TRUSTSTORE_PASSWORD_KEY, DEFAULT_VALUE)
        logger.info("${TRUSTSTORE_PASSWORD_KEY}: ${retrievedTruststorePassword}")

        // Assert
        assert retrievedTruststorePassword == DEFAULT_VALUE
        assert isSensitive
        assert !isProtected
    }

    /**
     * In the protection enabled scenario, a call to retrieve a sensitive property should return the raw value transparently.
     * @throws Exception
     */
    @Test
    public void testShouldGetUnprotectedValueOfSensitivePropertyWhenProtectedWithDefault() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"
        final String EXPECTED_KEYSTORE_PASSWORD = "thisIsABadKeystorePassword"
        final String DEFAULT_VALUE = "defaultValue"

        // Raw properties
        Properties rawProperties = new Properties()
        rawProperties.load(new File("src/test/resources/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties").newInputStream())
        final String RAW_KEYSTORE_PASSWORD = rawProperties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("Raw value for ${KEYSTORE_PASSWORD_KEY}: ${RAW_KEYSTORE_PASSWORD}")

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY, DEFAULT_VALUE)
        logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")

        // Assert
        assert retrievedKeystorePassword == EXPECTED_KEYSTORE_PASSWORD
        assert isSensitive
        assert isProtected
    }

    // TODO: Test getProtected with multiple providers

    /**
     * In the protection enabled scenario, a call to retrieve a sensitive property should handle if the internal cache of providers is empty.
     * @throws Exception
     */
    @Test
    public void testGetValueOfSensitivePropertyShouldHandleInvalidatedInternalCache() throws Exception {
        // Arrange
        final String KEYSTORE_PASSWORD_KEY = "nifi.security.keystorePasswd"
        final String EXPECTED_KEYSTORE_PASSWORD = "thisIsABadKeystorePassword"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        // Overwrite the internal cache
        properties.localProviderCache = [:]

        boolean isSensitive = properties.isPropertySensitive(KEYSTORE_PASSWORD_KEY)
        boolean isProtected = properties.isPropertyProtected(KEYSTORE_PASSWORD_KEY)
        logger.info("The property is ${isSensitive ? "sensitive" : "not sensitive"} and ${isProtected ? "protected" : "not protected"}")

        // Act
        String retrievedKeystorePassword = properties.getProperty(KEYSTORE_PASSWORD_KEY)
        logger.info("${KEYSTORE_PASSWORD_KEY}: ${retrievedKeystorePassword}")

        // Assert
        assert retrievedKeystorePassword == EXPECTED_KEYSTORE_PASSWORD
        assert isSensitive
        assert isProtected
    }

    @Test
    public void testShouldDetectIfPropertyIsProtected() throws Exception {
        // Arrange
        final String UNPROTECTED_PROPERTY_KEY = "nifi.security.truststorePasswd"
        final String PROTECTED_PROPERTY_KEY = "nifi.security.keystorePasswd"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        // Act
        boolean unprotectedPasswordIsSensitive = properties.isPropertySensitive(UNPROTECTED_PROPERTY_KEY)
        boolean unprotectedPasswordIsProtected = properties.isPropertyProtected(UNPROTECTED_PROPERTY_KEY)
        logger.info("${UNPROTECTED_PROPERTY_KEY} is ${unprotectedPasswordIsSensitive ? "SENSITIVE" : "NOT SENSITIVE"}")
        logger.info("${UNPROTECTED_PROPERTY_KEY} is ${unprotectedPasswordIsProtected ? "PROTECTED" : "NOT PROTECTED"}")
        boolean protectedPasswordIsSensitive = properties.isPropertySensitive(PROTECTED_PROPERTY_KEY)
        boolean protectedPasswordIsProtected = properties.isPropertyProtected(PROTECTED_PROPERTY_KEY)
        logger.info("${PROTECTED_PROPERTY_KEY} is ${protectedPasswordIsSensitive ? "SENSITIVE" : "NOT SENSITIVE"}")
        logger.info("${PROTECTED_PROPERTY_KEY} is ${protectedPasswordIsProtected ? "PROTECTED" : "NOT PROTECTED"}")

        // Assert
        assert unprotectedPasswordIsSensitive
        assert !unprotectedPasswordIsProtected

        protectedPasswordIsSensitive
        assert protectedPasswordIsProtected
    }

    @Test
    public void testShouldGetPercentageOfSensitivePropertiesProtected_0() throws Exception {
        // Arrange
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")

        logger.info("Sensitive property keys: ${properties.getSensitivePropertyKeys()}")
        logger.info("Protected property keys: ${properties.getProtectedPropertyKeys().keySet()}")

        // Act
        double percentProtected = properties.getPercentOfSensitivePropertiesProtected()
        logger.info("${percentProtected}% (${properties.getProtectedPropertyKeys().size()} of ${properties.getSensitivePropertyKeys().size()}) protected")

        // Assert
        assert percentProtected == 0.0
    }

    @Test
    public void testShouldGetPercentageOfSensitivePropertiesProtected_50() throws Exception {
        // Arrange
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        logger.info("Sensitive property keys: ${properties.getSensitivePropertyKeys()}")
        logger.info("Protected property keys: ${properties.getProtectedPropertyKeys().keySet()}")

        // Act
        double percentProtected = properties.getPercentOfSensitivePropertiesProtected()
        logger.info("${percentProtected}% (${properties.getProtectedPropertyKeys().size()} of ${properties.getSensitivePropertyKeys().size()}) protected")

        // Assert
        assert percentProtected == 50.0
    }

    @Test
    public void testShouldGetPercentageOfSensitivePropertiesProtected_100() throws Exception {
        // Arrange
        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi_with_all_sensitive_properties_protected_aes.properties")

        logger.info("Sensitive property keys: ${properties.getSensitivePropertyKeys()}")
        logger.info("Protected property keys: ${properties.getProtectedPropertyKeys().keySet()}")

        // Act
        double percentProtected = properties.getPercentOfSensitivePropertiesProtected()
        logger.info("${percentProtected}% (${properties.getProtectedPropertyKeys().size()} of ${properties.getSensitivePropertyKeys().size()}) protected")

        // Assert
        assert percentProtected == 100.0
    }

    @Test
    public void testInstanceWithNoProtectedPropertiesShouldNotLoadSPP() throws Exception {
        // Arrange
        NiFiProperties.@instance = null

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")
        assert properties.@localProviderCache?.isEmpty()

        logger.info("Has protected properties: ${properties.hasProtectedKeys()}")
        assert !properties.hasProtectedKeys()

        // Act
        Map localCache = properties.@localProviderCache
        logger.info("Internal cache ${localCache} has ${localCache.size()} providers loaded")

        // Assert
        assert localCache.isEmpty()
    }

    @Test
    public void testShouldSetProtectionKey() throws Exception {
        // Arrange
        NiFiProperties.@instance = null
        // The key is set in setUp()
        NiFiProperties.@protectionKey = null

        final String NEW_KEY = "some new key"

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")
        assert !properties.@protectionKey

        // Act
        properties.setProtectionKey(NEW_KEY)

        // Assert
        assert properties.@protectionKey == NEW_KEY
    }

    @Test
    public void testShouldNotAllowOverwriteOfProtectionKey() throws Exception {
        // Arrange
        NiFiProperties.@instance = null
        final String EXISTING_KEY = "some existing key"
        final String NEW_KEY = "some new key"

        // The key is set in setUp()
        NiFiProperties.@protectionKey = null

        NiFiProperties properties = loadFromFile("/NiFiProperties/conf/nifi.properties")
        assert !properties.@protectionKey
        properties.@protectionKey = EXISTING_KEY

        // Act
        def msg = shouldFail(IllegalStateException) {
            properties.setProtectionKey(NEW_KEY)
        }
        logger.expected(msg)

        // Assert
        assert msg == "Cannot overwrite existing NiFiProperties protection key"
        assert properties.@protectionKey == EXISTING_KEY
    }
}
