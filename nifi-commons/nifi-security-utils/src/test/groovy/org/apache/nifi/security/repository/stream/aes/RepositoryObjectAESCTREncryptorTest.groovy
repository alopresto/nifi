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
package org.apache.nifi.security.repository.stream.aes

import org.apache.nifi.security.kms.KeyProvider
import org.apache.nifi.security.util.EncryptionMethod
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.Security

@RunWith(JUnit4.class)
class RepositoryObjectAESCTREncryptorTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(RepositoryObjectAESCTREncryptorTest.class)

    private static final String KEY_HEX_128 = "0123456789ABCDEFFEDCBA9876543210"
    private static final String KEY_HEX_256 = KEY_HEX_128 * 2
    private static final String KEY_HEX = isUnlimitedStrengthCryptoAvailable() ? KEY_HEX_256 : KEY_HEX_128

    private static final String LOG_PACKAGE = "org.slf4j.simpleLogger.log.org.apache.nifi.security.repository.stream.aes"

    private static KeyProvider mockKeyProvider
    private static AESKeyedCipherProvider mockCipherProvider

    private static String ORIGINAL_LOG_LEVEL

    private RepositoryObjectAESCTREncryptor encryptor

    @BeforeClass
    static void setUpOnce() throws Exception {
        ORIGINAL_LOG_LEVEL = System.getProperty(LOG_PACKAGE)
        System.setProperty(LOG_PACKAGE, "DEBUG")

        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        mockKeyProvider = [
                getKey   : { String keyId ->
                    logger.mock("Requesting key ID: ${keyId}")
                    new SecretKeySpec(Hex.decode(KEY_HEX), "AES")
                },
                keyExists: { String keyId ->
                    logger.mock("Checking existence of ${keyId}")
                    true
                }] as KeyProvider

        mockCipherProvider = [
                getCipher: { EncryptionMethod em, SecretKey key, byte[] ivBytes, boolean encryptMode ->
                    logger.mock("Getting cipher for ${em} with IV ${Hex.toHexString(ivBytes)} encrypt ${encryptMode}")
                    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding")
                    cipher.init((encryptMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE) as int, key, new IvParameterSpec(ivBytes))
                    cipher
                }] as AESKeyedCipherProvider
    }

    @Before
    void setUp() throws Exception {

    }

    @After
    void tearDown() throws Exception {

    }

    @AfterClass
    static void tearDownOnce() throws Exception {
        if (ORIGINAL_LOG_LEVEL) {
            System.setProperty(LOG_PACKAGE, ORIGINAL_LOG_LEVEL)
        }
    }

    private static boolean isUnlimitedStrengthCryptoAvailable() {
        Cipher.getMaxAllowedKeyLength("AES") > 128
    }

    /**
     * Given arbitrary bytes, create an OutputStream, encrypt them, and persist with the (plaintext) encryption metadata, then recover
     */
    @Test
    void testShouldEncryptAndDecryptArbitraryBytes() {
        // Arrange
        final byte[] SERIALIZED_BYTES = "This is a plaintext message.".getBytes(StandardCharsets.UTF_8)
        logger.info("Serialized bytes (${SERIALIZED_BYTES.size()}): ${Hex.toHexString(SERIALIZED_BYTES)}")

        encryptor = new RepositoryObjectAESCTREncryptor()
        encryptor.initialize(mockKeyProvider)
        encryptor.setCipherProvider(mockCipherProvider)
        logger.info("Created ${encryptor}")

        String keyId = "K1"
        String recordId = "R1"
        logger.info("Using record ID ${recordId} and key ID ${keyId}")

        OutputStream encryptDestination = new ByteArrayOutputStream(256)

        byte[] decryptBytes = new byte[256]
        InputStream decryptDestination = new ByteArrayInputStream(decryptBytes)

        // Act
        OutputStream encryptedOutputStream = encryptor.encrypt(encryptDestination, recordId, keyId)
        encryptedOutputStream.write(SERIALIZED_BYTES)
        encryptedOutputStream.flush()
        encryptedOutputStream.close()

        byte[] encryptedBytes = encryptDestination.toByteArray()
        logger.info("Encrypted bytes: ${Hex.toHexString(encryptedBytes)}".toString())

        InputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes)

        InputStream decryptedInputStream = encryptor.decrypt(encryptedInputStream, recordId)
        byte[] recoveredBytes = new byte[SERIALIZED_BYTES.length]
        decryptedInputStream.read(recoveredBytes)
        logger.info("Decrypted data to: \n\t${Hex.toHexString(recoveredBytes)}")

        // Assert
        assert recoveredBytes == SERIALIZED_BYTES
        logger.info("Decoded (usually would be serialized schema record): ${new String(recoveredBytes, StandardCharsets.UTF_8)}")
    }

    /**
     * Test which demonstrates that normal mechanism of {@code OutputStream os = repository.write(contentClaim); os.write(content1); os.write(content2);} works because only one encryption metadata record is written (before {@code content1}). {@code content2} is written with the same recordId and keyId because the output stream is written to by the same {@code session.write()}
     */
    @Test
    void testShouldEncryptAndDecryptMultiplePiecesOfContent() {
        // Arrange
        final byte[] SERIALIZED_BYTES_1 = "This is plaintext content 1.".getBytes(StandardCharsets.UTF_8)
        final byte[] SERIALIZED_BYTES_2 = "This is plaintext content 2.".getBytes(StandardCharsets.UTF_8)
        logger.info("Serialized bytes 1 (${SERIALIZED_BYTES_1.size()}): ${Hex.toHexString(SERIALIZED_BYTES_1)}")
        logger.info("Serialized bytes 2 (${SERIALIZED_BYTES_2.size()}): ${Hex.toHexString(SERIALIZED_BYTES_2)}")

        encryptor = new RepositoryObjectAESCTREncryptor()
        encryptor.initialize(mockKeyProvider)
        encryptor.setCipherProvider(mockCipherProvider)
        logger.info("Created ${encryptor}")

        String keyId = "K1"
        String recordId = "R1"

        OutputStream encryptDestination = new ByteArrayOutputStream(512)

        // Act
        logger.info("Using record ID ${recordId} and key ID ${keyId}")
        OutputStream encryptedOutputStream = encryptor.encrypt(encryptDestination, recordId, keyId)
        encryptedOutputStream.write(SERIALIZED_BYTES_1)
        encryptedOutputStream.write(SERIALIZED_BYTES_2)

        encryptedOutputStream.flush()
        encryptedOutputStream.close()

        byte[] encryptedBytes = encryptDestination.toByteArray()
        logger.info("Encrypted bytes: ${Hex.toHexString(encryptedBytes)}".toString())

        InputStream encryptedInputStream = new ByteArrayInputStream(encryptedBytes)

        InputStream decryptedInputStream = encryptor.decrypt(encryptedInputStream, recordId)
        byte[] recoveredBytes1 = new byte[SERIALIZED_BYTES_1.length]
        decryptedInputStream.read(recoveredBytes1)
        logger.info("Decrypted data 1 to: \n\t${Hex.toHexString(recoveredBytes1)}")

        byte[] recoveredBytes2 = new byte[SERIALIZED_BYTES_2.length]
        decryptedInputStream.read(recoveredBytes2)
        logger.info("Decrypted data 2 to: \n\t${Hex.toHexString(recoveredBytes2)}")

        // Assert
        assert recoveredBytes1 == SERIALIZED_BYTES_1
        logger.info("Decoded 1 (usually would be serialized schema record): ${new String(recoveredBytes1, StandardCharsets.UTF_8)}")

        assert recoveredBytes2 == SERIALIZED_BYTES_2
        logger.info("Decoded 2 (usually would be serialized schema record): ${new String(recoveredBytes2, StandardCharsets.UTF_8)}")
    }
}
