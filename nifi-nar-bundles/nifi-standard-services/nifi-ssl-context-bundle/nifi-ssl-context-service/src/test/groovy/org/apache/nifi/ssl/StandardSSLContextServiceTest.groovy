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
package org.apache.nifi.ssl

import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Key
import java.security.KeyStore
import java.security.UnrecoverableKeyException

@RunWith(JUnit4.class)
class StandardSSLContextServiceTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(StandardSSLContextServiceTest.class)

    private static final String KEYSTORE_PASSWORD = "thisIsABadKeystorePassword"
    private static final String KEY_PASSWORD = "thisIsABadKeyPassword"

    private static final String DIFF_PASS_KEYSTORE_PATH = "src/test/resources/diffpass.jks"
    private static final String SAME_PASS_KEYSTORE_PATH = "src/test/resources/samepass.jks"

    private static final String DIFF_PASS_ALIAS = "diffpass"
    private static final String SAME_PASS_ALIAS = "samepass"

    @BeforeClass
    public static void setUpOnce() throws Exception {
        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testShouldGetCertificateEntryFromKeystoreWithDifferentKeyAndKeystorePassword() throws Exception {
        // Arrange
        KeyStore diffPass = KeyStore.getInstance("JKS")

        // Act
        diffPass.load(new File(DIFF_PASS_KEYSTORE_PATH).newInputStream(), KEYSTORE_PASSWORD as char[])
        List aliases = diffPass.aliases().collect { it }
        logger.info("Loaded keystore with different key and keystore passwords and ${aliases.size()} aliases: ${aliases.join(", ")}")
        Key diffPassKey = diffPass.getKey(DIFF_PASS_ALIAS, KEY_PASSWORD as char[])

        // Assert
        assert diffPassKey.algorithm == "RSA"
    }

    @Test
    public void testShouldNotGetCertificateEntryFromKeystoreWithDifferentKeyAndKeystorePassword() throws Exception {
        // Arrange
        KeyStore diffPass = KeyStore.getInstance("JKS")

        // Act
        diffPass.load(new File(DIFF_PASS_KEYSTORE_PATH).newInputStream(), KEYSTORE_PASSWORD as char[])
        List aliases = diffPass.aliases().collect { it }
        logger.info("Loaded keystore with different key and keystore passwords and ${aliases.size()} aliases: ${aliases.join(", ")}")
        def msg = shouldFail(UnrecoverableKeyException) {
            Key diffPassKey = diffPass.getKey(DIFF_PASS_ALIAS)
        }
        logger.expected(msg)

        // Assert
        assert msg =~ "Cannot recover key"
    }

    @Test
    public void testShouldGetCertificateEntryFromKeystoreWithSameKeyAndKeystorePassword() throws Exception {
        // Arrange
        KeyStore samePass = KeyStore.getInstance("JKS")

        // Act
        samePass.load(new File(SAME_PASS_KEYSTORE_PATH).newInputStream(), KEYSTORE_PASSWORD as char[])
        List aliases = samePass.aliases().collect { it }
        logger.info("Loaded keystore with same key and keystore passwords and ${aliases.size()} aliases: ${aliases.join(", ")}")
        Key samePassKey = samePass.getKey(SAME_PASS_ALIAS, KEYSTORE_PASSWORD as char[])

        // Assert
        assert samePassKey.algorithm == "RSA"
    }

    @Test
    public void testShouldNotGetCertificateEntryFromKeystoreWithSameKeyAndKeystorePassword() throws Exception {
        // Arrange
        KeyStore samePass = KeyStore.getInstance("JKS")

        // Act
        samePass.load(new File(SAME_PASS_KEYSTORE_PATH).newInputStream(), KEYSTORE_PASSWORD as char[])
        List aliases = samePass.aliases().collect { it }
        logger.info("Loaded keystore with same key and keystore passwords and ${aliases.size()} aliases: ${aliases.join(", ")}")
        def msg = shouldFail(UnrecoverableKeyException) {
            Key samePassKey = samePass.getKey(SAME_PASS_ALIAS)
        }
        logger.expected(msg)

        // Assert
        assert msg =~ "Cannot recover key"
    }

    @Test
    public void testShouldNotGetCertificateEntryFromKeystoreWithSameKeyAndKeystorePasswordUsingWrongKeyPassword() throws Exception {
        // Arrange
        KeyStore samePass = KeyStore.getInstance("JKS")

        // Act
        samePass.load(new File(SAME_PASS_KEYSTORE_PATH).newInputStream(), KEYSTORE_PASSWORD as char[])
        List aliases = samePass.aliases().collect { it }
        logger.info("Loaded keystore with same key and keystore passwords and ${aliases.size()} aliases: ${aliases.join(", ")}")
        def msg = shouldFail(UnrecoverableKeyException) {
            Key samePassKey = samePass.getKey(SAME_PASS_ALIAS, KEY_PASSWORD as char[])
        }
        logger.expected(msg)

        // Assert
        assert msg =~ "Cannot recover key"
    }
}
