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
package org.apache.nifi

import ch.qos.logback.classic.spi.LoggingEvent
import ch.qos.logback.core.AppenderBase
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
import org.slf4j.bridge.SLF4JBridgeHandler

import java.security.Security

@RunWith(JUnit4.class)
class NiFiGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(NiFiGroovyTest.class)

    private static String originalPropertiesPath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

    private static final String TEST_RES_PATH = NiFiGroovyTest.getClassLoader().getResource(".").toURI().getPath()
    private static final File workDir = new File("./target/work/jetty/")

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        SLF4JBridgeHandler.install()

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        logger.info("Identified test resources path as ${TEST_RES_PATH}")
    }

    @Before
    public void setUp() throws Exception {
        if (!workDir.exists()) {
            workDir.mkdirs()
        }
    }

    @After
    public void tearDown() throws Exception {
        NiFiProperties.@instance = null
        TestAppender.reset()
        System.setIn(System.in)
    }

    @AfterClass
    public static void tearDownOnce() {
        if (originalPropertiesPath) {
            System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, originalPropertiesPath)
        }
    }

    @Test
    public void testMainShouldHandleNoBootstrapKey() throws Exception {
        // Arrange
        assert !NiFiProperties.@instance
        def args = [] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi.properties")

        File canary = new File("${workDir.path}/canary-test.txt")
        canary.setWritable(true)
        canary.write("This is a canary file for ${getMethodName()}")
        assert canary.exists()

        // Act
        NiFi.main(args)

        // Assert

        // This is not the best way to test because it checks a side-effect
        assert !canary.exists()
    }

    @Test
    public void testMainShouldHandleNoBootstrapKeyWithProtectedProperties() throws Exception {
        // Arrange
        assert !NiFiProperties.@instance
        def args = [] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes_different_key.properties")

        // Act
        NiFi.main(args)

        // Assert
        assert TestAppender.events.last().toString() == "[ERROR] Failure to launch NiFi due to java.lang.IllegalStateException: No key provided from bootstrap"
    }

    @Test
    public void testMainShouldSplitCombinedArgs() throws Exception {
        // Arrange
        final String DIFFERENT_KEY = "0" * 64
        assert !NiFiProperties.@instance
        def args = ["-k ${DIFFERENT_KEY}"] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes_different_key.properties")

        // Act
        NiFi.main(args)

        // Assert
        NiFiProperties properties = NiFiProperties.getInstance()
        logger.info("NiFiProperties has protected properties: ${properties.hasProtectedKeys()}")

        // Ensure that there are protected properties, they are encrypted using AES/GCM (128/256 bit key), and they can be decrypted (raw value != retrieved value)
        assert properties.hasProtectedKeys()
        assert properties.getProtectedPropertyKeys().every { k, v ->
            String rawValue = properties.getRawProperty(k)
            logger.raw("${k} -> ${rawValue}")
            String retrievedValue = properties.getProperty(k)
            logger.decrypted("${k} -> ${retrievedValue}")

            v =~ "aes/gcm" && retrievedValue != rawValue
        }
    }

    @Test
    public void testMainShouldHandleBadArgs() throws Exception {
        // Arrange
        assert !NiFiProperties.@instance
        def args = ["-k"] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        // Act
        NiFi.main(args)

        // Assert
        assert TestAppender.events.last().toString() == "[ERROR] Failure to launch NiFi due to java.lang.IllegalArgumentException: The bootstrap process provided the -k flag but no key"
    }

    @Test
    public void testMainShouldHandleMalformedBootstrapKey() throws Exception {
        // Arrange
        assert !NiFiProperties.@instance
        def args = ["-k", "BAD KEY"] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes.properties")

        // Act
        NiFi.main(args)

        // Assert
        assert TestAppender.events.last().toString() == "[ERROR] Failure to launch NiFi due to java.lang.IllegalArgumentException: The key was not provided in valid hex format and of the correct length"
    }

    @Test
    public void testMainShouldSetBootstrapKeyFromArgs() throws Exception {
        // Arrange
        final String DIFFERENT_KEY = "0" * 64
        assert !NiFiProperties.@instance
        def args = ["-k", DIFFERENT_KEY] as String[]

        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, "${TEST_RES_PATH}/NiFiProperties/conf/nifi_with_sensitive_properties_protected_aes_different_key.properties")

        // Act
        NiFi.main(args)

        // Assert
        NiFiProperties properties = NiFiProperties.getInstance()
        logger.info("NiFiProperties has protected properties: ${properties.hasProtectedKeys()}")

        // Ensure that there are protected properties, they are encrypted using AES/GCM (128/256 bit key), and they can be decrypted (raw value != retrieved value)
        assert properties.hasProtectedKeys()
        assert properties.getProtectedPropertyKeys().every { k, v ->
            String rawValue = properties.getRawProperty(k)
            logger.raw("${k} -> ${rawValue}")
            String retrievedValue = properties.getProperty(k)
            logger.decrypted("${k} -> ${retrievedValue}")

            v =~ "aes/gcm" && retrievedValue != rawValue
        }
    }

    @Test
    public void testShouldValidateKeys() {
        // Arrange
        final List<String> VALID_KEYS = [
                "0" * 64, // 256 bit keys
                "ABCDEF01" * 8,
                "0123" * 8, // 128 bit keys
                "0123456789ABCDEFFEDCBA9876543210",
                "0123456789ABCDEFFEDCBA9876543210".toLowerCase(),
        ]

        // Act
        def isValid = VALID_KEYS.collectEntries { String key -> [(key): NiFi.isHexKeyValid(key)] }
        logger.info("Key validity: ${isValid}")

        // Assert
        assert isValid.every { k, v -> v }
    }

    @Test
    public void testShouldNotValidateInvalidKeys() {
        // Arrange
        final List<String> VALID_KEYS = [
                "0" * 63,
                "ABCDEFG1" * 8,
                "0123" * 9,
                "0123456789ABCDEFFEDCBA987654321",
                "0123456789ABCDEF FEDCBA9876543210".toLowerCase(),
                null,
                "",
                "        "
        ]

        // Act
        def isValid = VALID_KEYS.collectEntries { String key -> [(key): NiFi.isHexKeyValid(key)] }
        logger.info("Key validity: ${isValid}")

        // Assert
        assert isValid.every { k, v -> !v }
    }
}

public class TestAppender extends AppenderBase<LoggingEvent> {
    static List<LoggingEvent> events = new ArrayList<>();

    @Override
    protected void append(LoggingEvent e) {
        events.add(e);
    }

    public static void reset() {
        events.clear();
    }
}