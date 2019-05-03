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

package org.apache.nifi.toolkit.tls.v2.util

import org.apache.nifi.security.util.CertificateUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyPair
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate

@RunWith(JUnit4.class)
class TlsToolkitUtilTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(TlsToolkitUtilTest.class)

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder()

    @BeforeClass
    static void setUpOnce() {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() {
        super.setUp()

    }

    @After
    void tearDown() {

    }

    /**
     * Verifies that the passwords are the correct length and are different
     */
    @Test
    void testShouldGenerateRandomPassword() {
        // Arrange
        int times = 5
        logger.info("Running test ${times} times")

        def passwords = []

        // Act
        times.times { int i ->
            def password = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.generateRandomPassword()
            logger.info("Generated password: ${password}")
            passwords << password
        }

        // Assert
        assert passwords.size() == times
        assert passwords.unique() == passwords
        assert passwords.every { it =~ /[\w+\/]{30}/ }
    }

    @Test
    void testShouldGenerateRandomPasswordOfDifferentLength() {
        // Arrange
        int times = 5
        logger.info("Running test ${times} times")

        int customLength = 60

        def passwords = []

        // Act
        times.times { int i ->
            def password = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.generateRandomPassword(customLength)
            logger.info("Generated password: ${password}")
            passwords << password
        }

        // Assert
        assert passwords.size() == times
        assert passwords.unique() == passwords
        assert passwords.every { it =~ /[\w+\/]{${customLength}}/ }
    }

    @Test
    void testShouldEnforceMinimumLengthOfPassword() {
        // Arrange
        int customLength = 10

        // Act
        def msg = shouldFail() {
            def password = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.generateRandomPassword(customLength)
            logger.info("Generated password: ${password}")
        }

        // Assert
        assert msg == "The requested password length (${customLength} chars) cannot be less than the minimum password length (16 chars)".toString()
    }

    @Test
    void testShouldGenerateKeystoreFromExternalMaterial() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String TMP_KEYSTORE_PATH = keystoreFile.path
        keystoreFile.delete()
        logger.info("Keystore exists at ${TMP_KEYSTORE_PATH}: ${keystoreFile.exists()}")

        String alias = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.DEFAULT_ALIAS
        KeyPair keyPair = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.generateKeyPair()
        PrivateKey privateKey = keyPair.private
        X509Certificate caCert = CertificateUtils.generateSelfSignedX509Certificate(keyPair, org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.DEFAULT_DN, org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.DEFAULT_SIGNING_ALGORITHM, org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.DEFAULT_CERT_VALIDITY_DAYS)

        final String KEYSTORE_PASSWORD = "passwordpassword"

        // TODO: Override the output location in the constructor

        // Act
        def keystore = org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil.generateKeystoreFromExternalMaterial(caCert, privateKey, KEYSTORE_PASSWORD)
        logger.info("Generated keystore: ${keystore}")

        // Assert
        assert Collections.list(keystore.aliases()) == [alias]
        assert keystore.getKey(alias, KEYSTORE_PASSWORD.chars) == privateKey
        assert keystore.getCertificate(alias) == caCert
    }
}
