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
package org.apache.nifi.controller.repository.crypto


import org.apache.nifi.controller.repository.claim.ContentClaim
import org.apache.nifi.controller.repository.claim.StandardResourceClaimManager
import org.apache.nifi.controller.repository.util.DiskUtils
import org.apache.nifi.security.kms.KeyProvider
import org.apache.nifi.security.repository.RepositoryEncryptorUtils
import org.apache.nifi.security.repository.RepositoryObjectEncryptionMetadata
import org.apache.nifi.security.util.EncryptionMethod
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider
import org.apache.nifi.stream.io.StreamUtils
import org.apache.nifi.util.NiFiProperties
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
import javax.crypto.CipherInputStream
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.Security

@RunWith(JUnit4.class)
class EncryptedFileSystemRepositoryTest {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedFileSystemRepositoryTest.class)

    private static final String KEY_HEX_128 = "0123456789ABCDEFFEDCBA9876543210"
    private static final String KEY_HEX_256 = KEY_HEX_128 * 2
    private static final String KEY_HEX = isUnlimitedStrengthCryptoAvailable() ? KEY_HEX_256 : KEY_HEX_128

    private static KeyProvider mockKeyProvider
    private static AESKeyedCipherProvider mockCipherProvider

    private static String ORIGINAL_LOG_LEVEL

    public static final File helloWorldFile = new File("src/test/resources/hello.txt")

    private EncryptedFileSystemRepository repository = null
    private StandardResourceClaimManager claimManager = null
    private final File rootFile = new File("target/content_repository")
    private NiFiProperties nifiProperties
    private static final String LOG_PACKAGE = "org.slf4j.simpleLogger.log.org.apache.nifi.controller.repository.crypto"

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
                    Cipher cipher = Cipher.getInstance(em.algorithm)
                    cipher.init((encryptMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE) as int, key, new IvParameterSpec(ivBytes))
                    cipher
                }
        ] as AESKeyedCipherProvider
    }

    @Before
    void setUp() throws Exception {
        // TODO: Mock NiFiProperties w/ encrypted configs
        System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, EncryptedFileSystemRepositoryTest.class.getResource("/conf/nifi.properties").getFile())
        nifiProperties = NiFiProperties.createBasicNiFiProperties(null, null)
        if (rootFile.exists()) {
            DiskUtils.deleteRecursively(rootFile)
        }
        repository = new EncryptedFileSystemRepository(nifiProperties)
        claimManager = new StandardResourceClaimManager()
        repository.initialize(claimManager)
        repository.purge()
    }

    @After
    void tearDown() throws Exception {
        repository.shutdown()
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
     * Simple test to write encrypted content to the repository, independently read the persisted file to ensure the content is encrypted, and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldEncryptAndDecrypt() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        String plainContent = "hello"
        byte[] plainBytes = plainContent.bytes
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${Hex.toHexString(plainBytes)}")

        // Act
        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        // Independently access the persisted file and verify that the content is encrypted
        String persistedFilePath = getPersistedFilePath(claim)
        logger.verify("Persisted file: ${persistedFilePath}")
        byte[] persistedBytes = new File(persistedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${Hex.toHexString(persistedBytes)}")

        // TODO: Parse out EncryptionMetadata and ciphertext
        logger.verify("Persisted bytes (encrypted) (${persistedBytes.length}) [${Hex.toHexString(persistedBytes)[0..<16]}...] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedBytes.length != plainBytes.length
        assert persistedBytes != plainBytes
        // TODO: Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainContent.length(), persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) [${Hex.toHexString(persistedCipherBytes)}] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedCipherBytes != plainBytes

        // Verify that independent decryption works (basically ROAESCTRE#decrypt())
        RepositoryObjectEncryptionMetadata metadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(persistedBytes))
        logger.verify("Parsed encryption metadata: ${metadata}")
        Cipher verificationCipher = RepositoryEncryptorUtils.initCipher(mockCipherProvider, EncryptionMethod.AES_CTR, Cipher.DECRYPT_MODE, mockKeyProvider.getKey(metadata.keyId), metadata.ivBytes)
        logger.verify("Created cipher: ${verificationCipher}")

        // Skip the encryption metadata
        byte[] cipherBytes = RepositoryEncryptorUtils.extractCipherBytes(persistedBytes, metadata)
        CipherInputStream verificationCipherStream = new CipherInputStream(new ByteArrayInputStream(cipherBytes), verificationCipher)

        byte[] recoveredBytes = new byte[plainContent.length()]
        verificationCipherStream.read(recoveredBytes)
        logger.verify("Decrypted bytes (${recoveredBytes.length}): ${Hex.toHexString(recoveredBytes)} - ${new String(recoveredBytes, StandardCharsets.UTF_8)}")
        assert new String(recoveredBytes, StandardCharsets.UTF_8) == plainContent

        // Use the EFSR to decrypt the same content
        final InputStream inputStream = repository.read(claim)
        final byte[] buffer = new byte[plainContent.length()]
        StreamUtils.fillBuffer(inputStream, buffer)
        logger.info("Read bytes via repository (${buffer.length}): ${Hex.toHexString(buffer)}")

        // Assert
        assert new String(buffer, StandardCharsets.UTF_8) == plainContent
    }

    /**
     * Simple test to write multiple pieces of encrypted content to the repository and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldEncryptAndDecryptMultipleRecords() {
        // Arrange
        boolean isLossTolerant = false

        def content = [
                "This is a plaintext message. ",
                "Some,csv,data\ncol1,col2,col3",
                "Easy to read 0123456789abcdef"
        ]

        // Act
        def claims = content.collect { String pieceOfContent ->
            // Create a claim for each piece of content
            final ContentClaim claim = repository.create(isLossTolerant)

            // Write the content out
            final OutputStream out = repository.write(claim)
            out.write(pieceOfContent.bytes)
            out.flush()
            out.close()

            claim
        }

        claims.eachWithIndex { ContentClaim claim, int i ->
            String pieceOfContent = content[i]
            // Use the EFSR to decrypt the same content
            final InputStream inputStream = repository.read(claim)
            final byte[] buffer = new byte[pieceOfContent.length()]
            StreamUtils.fillBuffer(inputStream, buffer)
            logger.info("Read bytes via repository (${buffer.length}): ${Hex.toHexString(buffer)}")

            // Assert
            assert new String(buffer, StandardCharsets.UTF_8) == pieceOfContent
        }
    }

    /**
     * Simple test to write multiple pieces of encrypted content, each using a different encryption key, to the repository and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldEncryptAndDecryptMultipleRecordsWithDifferentKeys() {
        // Arrange
        boolean isLossTolerant = false

        def content = [
                "This is a plaintext message. ",
                "Some,csv,data\ncol1,col2,col3",
                "Easy to read 0123456789abcdef"
        ]

        // TODO: Set up mock key provider

        // Act
        def claims = content.collect { String pieceOfContent ->
            // Create a claim for each piece of content
            final ContentClaim claim = repository.create(isLossTolerant)

            // TODO: Increment the key ID used (set "active key ID")

            // Write the content out
            final OutputStream out = repository.write(claim)
            out.write(pieceOfContent.bytes)
            out.flush()
            out.close()

            claim
        }

        claims.eachWithIndex { ContentClaim claim, int i ->
            String pieceOfContent = content[i]
            // Use the EFSR to decrypt the same content
            final InputStream inputStream = repository.read(claim)
            final byte[] buffer = new byte[pieceOfContent.length()]
            StreamUtils.fillBuffer(inputStream, buffer)
            logger.info("Read bytes via repository (${buffer.length}): ${Hex.toHexString(buffer)}")

            // Assert
            assert new String(buffer, StandardCharsets.UTF_8) == pieceOfContent
        }
    }

    private String getPersistedFilePath(ContentClaim claim) {
        [rootFile, claim.resourceClaim.section, claim.resourceClaim.id].join(File.separator)
    }
}
