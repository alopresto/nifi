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
package org.apache.nifi.security.util.crypto.hkdf

import org.apache.commons.codec.binary.Hex
import org.apache.nifi.security.kms.CryptoUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Assume
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class HkdfTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(HkdfTest.class)

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
    void testShouldGetStaticSalt() {
        // Arrange
        byte[] expectedSalt16 = Hkdf.STATIC_SALT_16
        byte[] expectedSalt32 = Hkdf.STATIC_SALT_32
        byte[] expectedSalt64 = Hkdf.STATIC_SALT_64
        def expectedSalts = [expectedSalt16, expectedSalt32, expectedSalt64]
        expectedSalts.each {
            logger.info(" Expected salt [${it.size()}]: ${new String(it, "UTF-8").padLeft(64)} | ${it}")
        }

        // Act
        byte[] salt16 = Hkdf.getStaticSalt(16)
        byte[] salt32 = Hkdf.getStaticSalt(32)
        byte[] salt64 = Hkdf.getStaticSalt(64)
        def retrievedSalts = [salt16, salt32, salt64]
        retrievedSalts.each {
            logger.info("Retrieved salt [${it.size()}]: ${new String(it, "UTF-8").padLeft(64)} | ${it}")
        }

        // Assert
        assert salt16 == expectedSalt16
        assert salt32 == expectedSalt32
        assert salt64 == expectedSalt64
    }

    @Test
    void testShouldGetStaticSaltForUndefinedLengths() {
        // Arrange
        byte[] expectedSalt16 = Hkdf.STATIC_SALT_16
        logger.info(" Expected salt [${expectedSalt16.size()}]: ${new String(expectedSalt16, "UTF-8").padLeft(64)} | ${expectedSalt16}")

        // Act
        byte[] saltNegative1 = Hkdf.getStaticSalt(-1)
        byte[] salt0 = Hkdf.getStaticSalt(0)
        byte[] salt1 = Hkdf.getStaticSalt(1)
        byte[] salt15 = Hkdf.getStaticSalt(15)
        byte[] salt17 = Hkdf.getStaticSalt(17)
        byte[] salt33 = Hkdf.getStaticSalt(33)
        def retrievedSalts = ["-1": saltNegative1, "0": salt0, "1": salt1, "15": salt15, "17": salt17, "33": salt33]
        retrievedSalts.each { k, v ->
            logger.info("Retrieved salt [${k.padLeft(2)}]: ${new String(v, "UTF-8").padLeft(64)} | ${v}")
        }

        // Assert
        assert retrievedSalts.every { k, v -> v == expectedSalt16 }
    }

    @Test
    void testShouldDeriveKeyInBytesWithoutSalt() {
        // Arrange
        final int L = 16

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" // 16 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        String expectedOKMHex = "c53697c1fd1f6803c7c1b2f55286b9ee"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        byte[] retrievedOKM = Hkdf.deriveKey(ikm)
        logger.info("Retrieved OKM [${retrievedOKM.length}]: ${Hex.encodeHexString(retrievedOKM).padLeft(L * 2)} | ${retrievedOKM}")

        // Assert
        assert retrievedOKM == expectedOKM
        assert retrievedOKM.length == ikm.length
    }

    @Test
    void testShouldDeriveKeyInBytesWithSalt() {
        // Arrange
        final int L = 16

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" // 16 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        byte[] salt = Hkdf.getStaticSalt(16)
        final String SALT_HEX = Hex.encodeHexString(salt) // 16 bytes
        logger.info("Provided salt [${salt.size()}]: ${SALT_HEX.padLeft(L * 2)} | ${salt}")

        String expectedOKMHex = "c53697c1fd1f6803c7c1b2f55286b9ee"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        byte[] retrievedOKM = Hkdf.deriveKey(salt, ikm)
        logger.info("Retrieved OKM [${retrievedOKM.length}]: ${Hex.encodeHexString(retrievedOKM).padLeft(L * 2)} | ${retrievedOKM}")

        // Assert
        assert retrievedOKM == expectedOKM
        assert retrievedOKM.length == ikm.length
    }

    @Test
    void testShouldDeriveKeyInHexWithoutSalt() {
        // Arrange
        final int L = 16

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" // 16 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        String expectedOKMHex = "c53697c1fd1f6803c7c1b2f55286b9ee"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        String retrievedOKMHex = Hkdf.deriveKeyHex(IKM_HEX)
        logger.info("Retrieved OKM [${retrievedOKMHex.length() / 2}]: ${retrievedOKMHex.padLeft(L * 2)} | ${Hex.decodeHex(retrievedOKMHex)}")

        // Assert
        assert retrievedOKMHex == expectedOKMHex
        assert retrievedOKMHex.length() == IKM_HEX.length()
    }

    @Test
    void testShouldDeriveKeyInHexWithSalt() {
        // Arrange
        final int L = 16

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" // 16 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        byte[] salt = Hkdf.getStaticSalt(16)
        final String SALT_HEX = Hex.encodeHexString(salt) // 16 bytes
        logger.info("Provided salt [${salt.size()}]: ${SALT_HEX.padLeft(L * 2)} | ${salt}")

        String expectedOKMHex = "c53697c1fd1f6803c7c1b2f55286b9ee"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        String retrievedOKMHex = Hkdf.deriveKeyHex(SALT_HEX, IKM_HEX)
        logger.info("Retrieved OKM [${retrievedOKMHex.length() / 2}]: ${retrievedOKMHex.padLeft(L * 2)} | ${Hex.decodeHex(retrievedOKMHex)}")

        // Assert
        assert retrievedOKMHex == expectedOKMHex
        assert retrievedOKMHex.length() == IKM_HEX.length()
    }

    @Test
    void testShouldDerive32ByteKeyInHexWithoutSalt() {
        // Arrange
        Assume.assumeTrue("JCE Unlimited Strength Jurisdiction Policies must be installed", CryptoUtils.isUnlimitedStrengthCryptoAvailable())

        final int L = 32

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" * 2 // 32 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        String expectedOKMHex = "8d818b9ba543a4c554f98fea1fa256f11377bf63b07f3c38ab6555c2553d33fd"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        String retrievedOKMHex = Hkdf.deriveKeyHex(IKM_HEX)
        logger.info("Retrieved OKM [${retrievedOKMHex.length() / 2}]: ${retrievedOKMHex.padLeft(L * 2)} | ${Hex.decodeHex(retrievedOKMHex)}")

        // Assert
        assert retrievedOKMHex == expectedOKMHex
        assert retrievedOKMHex.length() == IKM_HEX.length()
    }

    @Test
    void testShouldDerive32ByteKeyInHexWithSalt() {
        // Arrange
        Assume.assumeTrue("JCE Unlimited Strength Jurisdiction Policies must be installed", CryptoUtils.isUnlimitedStrengthCryptoAvailable())

        final int L = 32

        final String IKM_HEX = "0123456789ABCDEFFEDCBA9876543210" * 2 // 32 bytes
        byte[] ikm = Hex.decodeHex(IKM_HEX)
        logger.info(" Provided IKM [${ikm.size()}]: ${IKM_HEX.padLeft(L * 2)} | ${ikm}")

        byte[] salt = Hkdf.getStaticSalt(32)
        final String SALT_HEX = Hex.encodeHexString(salt) // 32 bytes
        logger.info("Provided salt [${salt.size()}]: ${SALT_HEX.padLeft(L * 2)} | ${salt}")

        String expectedOKMHex = "8d818b9ba543a4c554f98fea1fa256f11377bf63b07f3c38ab6555c2553d33fd"
        byte[] expectedOKM = Hex.decodeHex(expectedOKMHex)
        logger.info(" Expected OKM [${expectedOKM.size()}]: ${expectedOKMHex.padLeft(L * 2)} | ${expectedOKM}")

        // Act
        String retrievedOKMHex = Hkdf.deriveKeyHex(SALT_HEX, IKM_HEX)
        logger.info("Retrieved OKM [${retrievedOKMHex.length() / 2}]: ${retrievedOKMHex.padLeft(L * 2)} | ${Hex.decodeHex(retrievedOKMHex)}")

        // Assert
        assert retrievedOKMHex == expectedOKMHex
        assert retrievedOKMHex.length() == IKM_HEX.length()
    }
}
