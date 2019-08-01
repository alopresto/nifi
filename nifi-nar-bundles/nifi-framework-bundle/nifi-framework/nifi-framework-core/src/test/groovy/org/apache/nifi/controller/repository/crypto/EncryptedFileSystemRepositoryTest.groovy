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
import org.apache.nifi.security.kms.StaticKeyProvider
import org.apache.nifi.security.repository.RepositoryEncryptorUtils
import org.apache.nifi.security.repository.RepositoryObjectEncryptionMetadata
import org.apache.nifi.security.util.EncryptionMethod
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider
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
import java.nio.file.Path
import java.security.Security

import static groovy.test.GroovyAssert.shouldFail

@RunWith(JUnit4.class)
class EncryptedFileSystemRepositoryTest {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedFileSystemRepositoryTest.class)

    private static final String KEY_HEX_128 = "0123456789ABCDEFFEDCBA9876543210"
    private static final String KEY_HEX_256 = KEY_HEX_128 * 2
    private static final String KEY_HEX_1 = isUnlimitedStrengthCryptoAvailable() ? KEY_HEX_256 : KEY_HEX_128

    private static final String KEY_HEX_2 = "00" * (isUnlimitedStrengthCryptoAvailable() ? 32 : 16)
    private static final String KEY_HEX_3 = "AA" * (isUnlimitedStrengthCryptoAvailable() ? 32 : 16)

    private static final String KEY_ID_1 = "K1"
    private static final String KEY_ID_2 = "K2"
    private static final String KEY_ID_3 = "K3"

    private static AESKeyedCipherProvider mockCipherProvider

    private static String ORIGINAL_LOG_LEVEL

    private EncryptedFileSystemRepository repository = null
    private final File rootFile = new File("target/content_repository")
    private NiFiProperties nifiProperties
    private static final String LOG_PACKAGE = "org.slf4j.simpleLogger.log.org.apache.nifi.controller.repository.crypto"

    // Mapping of key IDs to keys
    final def KEYS = [
            (KEY_ID_1): new SecretKeySpec(Hex.decode(KEY_HEX_1), "AES"),
            (KEY_ID_2): new SecretKeySpec(Hex.decode(KEY_HEX_2), "AES"),
            (KEY_ID_3): new SecretKeySpec(Hex.decode(KEY_HEX_3), "AES"),
    ]
    private static final String DEFAULT_NIFI_PROPS_PATH = "/conf/nifi.properties"

    private static final Map<String, String> DEFAULT_ENCRYPTION_PROPS = [
            (NiFiProperties.CONTENT_REPOSITORY_IMPLEMENTATION)                              : "org.apache.nifi.controller.repository.crypto.EncryptedFileSystemRepository",
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_ID)                           : KEY_ID_1,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY)                              : KEY_HEX_1,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_PROVIDER_IMPLEMENTATION_CLASS): StaticKeyProvider.class.name,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_PROVIDER_LOCATION)            : ""
    ]

    @BeforeClass
    static void setUpOnce() throws Exception {
        ORIGINAL_LOG_LEVEL = System.getProperty(LOG_PACKAGE)
        System.setProperty(LOG_PACKAGE, "DEBUG")

        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

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
        // Use mock NiFiProperties w/ encrypted configs
        repository = initializeRepository()
    }

    private EncryptedFileSystemRepository initializeRepository(String nifiPropertiesPath = DEFAULT_NIFI_PROPS_PATH, Map<String, String> additionalProperties = DEFAULT_ENCRYPTION_PROPS) {
        nifiProperties = NiFiProperties.createBasicNiFiProperties(EncryptedFileSystemRepositoryTest.class.getResource(nifiPropertiesPath).path, additionalProperties)
        if (rootFile.exists()) {
            DiskUtils.deleteRecursively(rootFile)
        }

        EncryptedFileSystemRepository repository = new EncryptedFileSystemRepository(nifiProperties)
        StandardResourceClaimManager claimManager = new StandardResourceClaimManager()
        repository.initialize(claimManager)
        repository.purge()
        logger.info("Created EFSR with nifi.properties [${nifiPropertiesPath}] and ${additionalProperties.size()} additional properties: ${additionalProperties}")

        repository
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

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

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

        logger.verify("Persisted bytes (encrypted) (${persistedBytes.length}) [${Hex.toHexString(persistedBytes)[0..<16]}...] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedBytes.length != plainBytes.length
        assert persistedBytes != plainBytes

        // Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainContent.length(), persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) [${Hex.toHexString(persistedCipherBytes)}] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedCipherBytes != plainBytes

        // Verify that independent decryption works (basically ROAESCTRE#decrypt())
        RepositoryObjectEncryptionMetadata metadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(persistedBytes))
        logger.verify("Parsed encryption metadata: ${metadata}")
        assert metadata.keyId == mockKeyProvider.getAvailableKeyIds().first()
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
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${Hex.toHexString(retrievedContent)}")

        // Assert
        assert new String(retrievedContent, StandardCharsets.UTF_8) == plainContent
    }

    /**
     * Simple test to write encrypted image content to the repository, independently read the persisted file to ensure the content is encrypted, and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldEncryptAndDecryptImage() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File image = new File("src/test/resources/encrypted_content_repo.png")
        byte[] plainBytes = image.bytes
        logger.info("Writing \"${image.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        // Act
        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        // Independently access the persisted file and verify that the content is encrypted
        String persistedFilePath = getPersistedFilePath(claim)
        logger.verify("Persisted file: ${persistedFilePath}")
        byte[] persistedBytes = new File(persistedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Verify the persisted bytes are not the plain bytes
        logger.verify("Persisted bytes (encrypted) (${persistedBytes.length}) ${pba(persistedBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedBytes.length != plainBytes.length
        assert persistedBytes != plainBytes

        // Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainBytes.length, persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) ${pba(persistedCipherBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedCipherBytes != plainBytes

        // Use the EFSR to decrypt the same content
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

        // Assert
        assert retrievedContent == plainBytes
    }

    /**
     * Simple test to write multiple pieces of encrypted content to the repository and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldEncryptAndDecryptMultipleRecords() {
        // Arrange
        boolean isLossTolerant = false

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

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
            byte[] retrievedContent = inputStream.bytes
            logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

            // Assert
            assert new String(retrievedContent, StandardCharsets.UTF_8) == pieceOfContent
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
                "K1": "This is a plaintext message. ",
                "K2": "Some,csv,data\ncol1,col2,col3",
                "K3": "Easy to read 0123456789abcdef"
        ]

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider

        int i = 0

        // Act
        def claims = content.collectEntries { String keyId, String pieceOfContent ->
            // Increment the key ID used (set "active key ID")
            repository.setActiveKeyId(keyId)
            logger.info("Set key ID for content ${i++} to ${keyId}")

            // Create a claim for each piece of content
            final ContentClaim claim = repository.create(isLossTolerant)


            // Write the content out
            final OutputStream out = repository.write(claim)
            out.write(pieceOfContent.bytes)
            out.flush()
            out.close()

            [keyId, claim]
        } as Map<String, ContentClaim>

        // Manually verify different key IDs used for each claim
        claims.each { String keyId, ContentClaim claim ->
            // Independently access the persisted file and verify that the content is encrypted
            logger.info("Manual verification of record ID ${EncryptedFileSystemRepository.getRecordId(claim)}")
            String persistedFilePath = getPersistedFilePath(claim)
            logger.verify("Persisted file: ${persistedFilePath}")
            byte[] persistedBytes = new File(persistedFilePath).bytes
            logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

            // Skip to the section for this content claim
            long start = claim.offset
            long end = claim.offset + claim.length
            byte[] contentSection = persistedBytes[start..<end]
            logger.verify("Extracted ${contentSection.length} bytes from ${start} to <${end}")

            // Verify that the persisted keyId is what was expected
            RepositoryObjectEncryptionMetadata metadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(contentSection))
            logger.verify("Parsed encryption metadata: ${metadata}")
            assert metadata.keyId == keyId
        }

        // Assert that the claims can be decrypted
        claims.each { String keyId, ContentClaim claim ->
            String pieceOfContent = content[keyId]
            // Use the EFSR to decrypt the same content
            final InputStream inputStream = repository.read(claim)
            byte[] retrievedContent = inputStream.bytes
            logger.info("Read bytes via repository (${retrievedContent.length}): ${Hex.toHexString(retrievedContent)}")

            // Assert
            assert new String(retrievedContent, StandardCharsets.UTF_8) == pieceOfContent
        }
    }

    /**
     * Simple test to write encrypted content to the repository, independently read the persisted file to ensure the content is encrypted, and then retrieve & decrypt via the repository.
     */
    @Test
    void testShouldValidateActiveKeyId() {
        // Arrange

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider

        def validKeyIds = mockKeyProvider.getAvailableKeyIds()
        def invalidKeyIds = [null, "", "   ", "K4"]


        // Act
        validKeyIds.each { String keyId ->
            repository.setActiveKeyId(keyId)

            // Assert
            assert repository.getActiveKeyId() == keyId
        }

        // Reset to empty
        repository.@activeKeyId = null
        invalidKeyIds.collect { String invalidKeyId ->
            repository.setActiveKeyId(invalidKeyId)

            // Assert
            assert repository.getActiveKeyId() == null
        }
    }

    /**
     * Simple test to show blocking on uninitialized key ID and key provider.
     */
    @Test
    void testWriteShouldRequireActiveKeyId() {
        // Arrange
        repository.@activeKeyId = null

        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        String plainContent = "hello"
        byte[] plainBytes = plainContent.bytes
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${pba(plainBytes)}")

        // Act
        def msg = shouldFail(Exception) {
            final OutputStream out = repository.write(claim)
            out.write(plainBytes)
            out.flush()
            out.close()
        }

        // Assert
        assert msg.localizedMessage == "Error creating encrypted content repository output stream"
        assert msg.cause.localizedMessage =~ "The .* record and key ID cannot be missing"
    }

    /**
     * Simple test to show no blocking on uninitialized key ID to retrieve content.
     */
    @Test
    void testReadShouldNotRequireActiveKeyId() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.availableKeyIds.first())

        String plainContent = "hello"
        byte[] plainBytes = plainContent.bytes
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${pba(plainBytes)}")

        // Write the encrypted content to the repository
        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        // Reset the active key ID to null
        repository.@activeKeyId = null

        // Act
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

        // Assert
        assert new String(retrievedContent, StandardCharsets.UTF_8) == plainContent
    }

    /**
     * Test to configure repository instance from nifi.properties.
     */
    @Test
    void testConstructorShouldReadFromNiFiProperties() {
        // Arrange

        // Remove the generic repository instance
        repository.purge()
        repository.cleanup()
        repository.shutdown()
        repository = null

        // Create a new repository with the encryption properties
        repository = initializeRepository(DEFAULT_NIFI_PROPS_PATH, DEFAULT_ENCRYPTION_PROPS)

        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Assert implicit configuration of necessary fields by encrypting and decrypting one record
        String plainContent = "hello"
        byte[] plainBytes = plainContent.bytes
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${Hex.toHexString(plainBytes)}")

        // Write the encrypted content to the repository
        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        // Act
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${Hex.toHexString(retrievedContent)}")

        // Assert
        assert new String(retrievedContent, StandardCharsets.UTF_8) == plainContent
    }

    /**
     * Simple test to ensure that when content is imported from an InputStream, it is encrypted.
     */
    @Test
    void testImportFromInputStreamShouldEncryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File image = new File("src/test/resources/bgBannerFoot.png")
        byte[] plainBytes = image.bytes
        logger.info("Writing \"${image.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        // Act
        final long bytesRead = repository.importFrom(image.newInputStream(), claim)
        logger.info("Read ${bytesRead} bytes from ${image.name} into ${claim.resourceClaim.id}")

        // Independently access the persisted file and verify that the content is encrypted
        String persistedFilePath = getPersistedFilePath(claim)
        logger.verify("Persisted file: ${persistedFilePath}")
        byte[] persistedBytes = new File(persistedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Parse out EncryptionMetadata and ciphertext
        logger.verify("Persisted bytes (encrypted) (${persistedBytes.length}) ${pba(persistedBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedBytes.length != plainBytes.length
        assert persistedBytes != plainBytes
        // Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainBytes.length, persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) ${pba(persistedCipherBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedCipherBytes != plainBytes

        // Use the EFSR to decrypt the same content
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

        // Assert
        assert retrievedContent == plainBytes
    }

    /**
     * Simple test to ensure that when content is imported from a path, it is encrypted.
     */
    @Test
    void testImportFromPathShouldEncryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File image = new File("src/test/resources/bgBannerFoot.png")
        byte[] plainBytes = image.bytes
        logger.info("Writing \"${image.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        // Act
        final long bytesRead = repository.importFrom(image.toPath(), claim)
        logger.info("Read ${bytesRead} bytes from ${image.name} into ${claim.resourceClaim.id}")

        // Independently access the persisted file and verify that the content is encrypted
        String persistedFilePath = getPersistedFilePath(claim)
        logger.verify("Persisted file: ${persistedFilePath}")
        byte[] persistedBytes = new File(persistedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Parse out EncryptionMetadata and ciphertext
        logger.verify("Persisted bytes (encrypted) (${persistedBytes.length}) ${pba(persistedBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedBytes.length != plainBytes.length
        assert persistedBytes != plainBytes
        // Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainBytes.length, persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) ${pba(persistedCipherBytes)} != plain bytes (${plainBytes.length}) ${pba(plainBytes)}")
        assert persistedCipherBytes != plainBytes

        // Use the EFSR to decrypt the same content
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

        // Assert
        assert retrievedContent == plainBytes
    }

    /**
     * Simple test to ensure that when content is exported to an OutputStream, it is decrypted.
     */
    @Test
    void testExportToOutputStreamShouldDecryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File image = new File("src/test/resources/bgBannerFoot.png")
        byte[] plainBytes = image.bytes
        logger.info("Writing \"${image.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        final OutputStream outputStream = new ByteArrayOutputStream()

        // Act
        final long bytesWritten = repository.exportTo(claim, outputStream)
        logger.info("Wrote ${bytesWritten} bytes from ${claim.resourceClaim.id} into OutputStream")

        // Independently access the output stream and verify that the content is plain text
        byte[] exportedBytes = outputStream.toByteArray()
        logger.info("Read bytes from output stream (${exportedBytes.length}): ${pba(exportedBytes)}")

        // Assert
        assert exportedBytes == plainBytes
    }

    /**
     * Simple test to ensure that when a subset of content is exported to an OutputStream, it is decrypted.
     */
    @Test
    void testExportSubsetToOutputStreamShouldDecryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File longText = new File("src/test/resources/longtext.txt")
        byte[] plainBytes = longText.bytes
        logger.info("Writing \"${longText.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        final OutputStream outputStream = new ByteArrayOutputStream()

        // Act
        long offset = 100
        long length = 50
        logger.info("Exporting claim ${claim} (offset: ${offset}, length: ${length}) to output stream")
        logger.info("Expecting these bytes from plain content: ${pba(plainBytes[offset..<(offset + length)] as byte[])}")

        final long bytesWritten = repository.exportTo(claim, outputStream, offset, length)
        logger.info("Wrote ${bytesWritten} bytes from ${claim.resourceClaim.id} into OutputStream")

        // Independently access the output stream and verify that the content is plain text
        byte[] exportedBytes = outputStream.toByteArray()
        logger.info("Read bytes from output stream (${exportedBytes.length}): ${pba(exportedBytes)}")

        // Assert
        assert exportedBytes == plainBytes[offset..<(offset + length)] as byte[]
        assert exportedBytes.length == length
        assert bytesWritten == length
    }

    /**
     * Simple test to ensure that when content is exported to a path, it is decrypted.
     */
    @Test
    void testExportToPathShouldDecryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File image = new File("src/test/resources/bgBannerFoot.png")
        byte[] plainBytes = image.bytes
        logger.info("Writing \"${image.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        final File tempOutputFile = new File("target/exportedContent")
        final Path tempPath = tempOutputFile.toPath()

        // Act
        final long bytesWritten = repository.exportTo(claim, tempPath, false)
        logger.info("Wrote ${bytesWritten} bytes from ${claim.resourceClaim.id} into path ${tempPath}")

        // Independently access the path and verify that the content is plain text
        byte[] exportedBytes = tempOutputFile.bytes
        logger.info("Read bytes from path (${exportedBytes.length}): ${pba(exportedBytes)}")

        // Assert
        try {
            assert exportedBytes == plainBytes
        } finally {
            // Clean up
            tempOutputFile.delete()
        }
    }

    /**
     * Simple test to ensure that when a subset of content is exported to a path, it is decrypted.
     */
    @Test
    void testExportSubsetToPathShouldDecryptContent() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File longText = new File("src/test/resources/longtext.txt")
        byte[] plainBytes = longText.bytes
        logger.info("Writing \"${longText.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        final File tempOutputFile = new File("target/exportedContent")
        final Path tempPath = tempOutputFile.toPath()

        // Act
        long offset = 100
        long length = 50
        logger.info("Exporting claim ${claim} (offset: ${offset}, length: ${length}) to output stream")
        logger.info("Expecting these bytes from plain content: ${pba(plainBytes[offset..<(offset + length)] as byte[])}")

        final long bytesWritten = repository.exportTo(claim, tempPath, false, offset, length)
        logger.info("Wrote ${bytesWritten} bytes from ${claim.resourceClaim.id} into path ${tempPath}")

        // Independently access the path and verify that the content is plain text
        byte[] exportedBytes = tempOutputFile.bytes
        logger.info("Read bytes from path (${exportedBytes.length}): ${pba(exportedBytes)}")

        // Assert
        try {
            assert exportedBytes == plainBytes[offset..<(offset + length)] as byte[]
            assert exportedBytes.length == length
            assert bytesWritten == length
        } finally {
            // Clean up
            tempOutputFile.delete()
        }
    }

    /**
     * Simple test to clone encrypted content claim and ensure that the cloned encryption metadata accurately reflects the new claim and allows for decryption.
     */
    @Test
    void testCloneShouldUpdateEncryptionMetadata() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim = repository.create(isLossTolerant)

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File textFile = new File("src/test/resources/longtext.txt")
        byte[] plainBytes = textFile.bytes
        logger.info("Writing \"${textFile.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        // Write to the content repository (encrypted)
        final OutputStream out = repository.write(claim)
        out.write(plainBytes)
        out.flush()
        out.close()

        // Independently access the persisted file and verify that the content is encrypted
        String persistedFilePath = getPersistedFilePath(claim)
        logger.verify("Persisted file: ${persistedFilePath}")
        byte[] persistedBytes = new File(persistedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Verify that the cipher bytes are the same length but not the same bytes (strip encryption metadata)
        byte[] persistedCipherBytes = Arrays.copyOfRange(persistedBytes, persistedBytes.length - plainBytes.length, persistedBytes.length)
        logger.verify("Persisted bytes (encrypted) (last ${persistedCipherBytes.length}) [${Hex.toHexString(persistedCipherBytes)}] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedCipherBytes != plainBytes

        // Extract the persisted encryption metadata
        RepositoryObjectEncryptionMetadata metadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(persistedBytes))
        logger.verify("Parsed encryption metadata: ${metadata}")
        assert metadata.keyId == mockKeyProvider.getAvailableKeyIds().first()

        // Act

        // Clone the content claim
        logger.info("Preparing to clone claim ${claim}")
        ContentClaim clonedClaim = repository.clone(claim, isLossTolerant)
        logger.info("Cloned claim ${claim} to ${clonedClaim}")

        // Independently access the persisted file and verify that the content is encrypted
        String persistedClonedFilePath = getPersistedFilePath(clonedClaim)
        logger.verify("Persisted file: ${persistedClonedFilePath}")
        int originalPersistedBytesLength = persistedBytes.length
        persistedBytes = new File(persistedClonedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Verify that the cipher bytes are the same length but not the same bytes (skipping the initial persisted claim)
        byte[] persistedClonedBytes = Arrays.copyOfRange(persistedBytes, originalPersistedBytesLength, persistedBytes.length)
        logger.verify("Persisted cloned bytes (encrypted) (last ${persistedClonedBytes.length}) [${Hex.toHexString(persistedClonedBytes)}] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedClonedBytes != plainBytes

        // Extract the persisted encryption metadata for the cloned claim
        RepositoryObjectEncryptionMetadata clonedMetadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(persistedClonedBytes))
        logger.verify("Parsed cloned encryption metadata: ${clonedMetadata}")
        assert clonedMetadata.keyId == mockKeyProvider.getAvailableKeyIds().first()

        // Use the EFSR to decrypt the original claim content
        final InputStream inputStream = repository.read(claim)
        byte[] retrievedContent = inputStream.bytes
        logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

        // Use the EFSR to decrypt the cloned claim content
        final InputStream clonedInputStream = repository.read(clonedClaim)
        byte[] retrievedClonedContent = clonedInputStream.bytes
        logger.info("Read cloned bytes via repository (${retrievedClonedContent.length}): ${pba(retrievedClonedContent)}")

        // Assert
        assert retrievedContent == plainBytes
        assert retrievedClonedContent == plainBytes
    }

    // TODO: Test merge

    /**
     * Simple test to merge two encrypted content claims and ensure that the merged encryption metadata accurately reflects the new claim and allows for decryption.
     */
    @Test
    void testMergeShouldUpdateEncryptionMetadata() {
        // Arrange
        boolean isLossTolerant = false
        final ContentClaim claim1 = repository.create(isLossTolerant)
        final ContentClaim claim2 = repository.create(isLossTolerant)
        def claims = [claim1, claim2]

        // Set up mock key provider and inject into repository
        KeyProvider mockKeyProvider = createMockKeyProvider()
        repository.keyProvider = mockKeyProvider
        repository.setActiveKeyId(mockKeyProvider.getAvailableKeyIds().first())

        File textFile = new File("src/test/resources/longtext.txt")
        byte[] plainBytes = textFile.bytes
        String plainContent = textFile.text
        int contentHalfLength = plainContent.size().intdiv(2)
        String content1 = plainContent[0..<contentHalfLength]
        String content2 = plainContent[contentHalfLength..-1]
        def content = [content1, content2]

        // TODO: Use small content for ease of decryption analysis
//        content = ["This is the first piece of content. ", "This is the second piece of content. "]
//        plainContent = content.join("")
//        plainBytes = plainContent.bytes

        logger.info("Writing \"${textFile.name}\" (${plainBytes.length}): ${pba(plainBytes)}")

        // Write each piece of content to the respective claim
        claims.eachWithIndex { ContentClaim claim, int i ->
            // Write to the content repository (encrypted)
            final OutputStream out = repository.write(claim)
            out.write(content[i].bytes)
            out.flush()
            out.close()
        }

        // Act

        // Merge the two content claims
        logger.info("Preparing to merge claims ${claims}")
        ContentClaim mergedClaim = repository.create(isLossTolerant)
        // The header, footer, and demarcator are null in this case
        long bytesWrittenDuringMerge = repository.merge(claims, mergedClaim, null, null, null)
        logger.info("Merged ${claims.size()} claims (${bytesWrittenDuringMerge} bytes) to ${mergedClaim}")

        // Independently access the persisted file and verify that the content is encrypted
        String persistedMergedFilePath = getPersistedFilePath(mergedClaim)
        logger.verify("Persisted file: ${persistedMergedFilePath}")
        def persistedBytes = new File(persistedMergedFilePath).bytes
        logger.verify("Read bytes (${persistedBytes.length}): ${pba(persistedBytes)}")

        // Extract the merged claim (using the claim offset)
        byte[] persistedMergedBytes = Arrays.copyOfRange(persistedBytes, mergedClaim.offset as int, persistedBytes.length)
        logger.verify("Persisted merged bytes (encrypted) (last ${persistedMergedBytes.length}) [${Hex.toHexString(persistedMergedBytes)}] != plain bytes (${plainBytes.length}) [${Hex.toHexString(plainBytes)}]")
        assert persistedMergedBytes != plainBytes

        // Extract the persisted encryption metadata for the merged claim
        RepositoryObjectEncryptionMetadata mergedMetadata = RepositoryEncryptorUtils.extractEncryptionMetadata(new ByteArrayInputStream(persistedMergedBytes))
        logger.verify("Parsed merged encryption metadata: ${mergedMetadata}")
        assert mergedMetadata.keyId == mockKeyProvider.getAvailableKeyIds().first()

        // Ensure the persisted bytes are encrypted
        Cipher verificationCipher = RepositoryEncryptorUtils.initCipher(mockCipherProvider, EncryptionMethod.AES_CTR, Cipher.DECRYPT_MODE, mockKeyProvider.getKey(mergedMetadata.keyId), mergedMetadata.ivBytes)
        logger.verify("Created cipher: ${verificationCipher}")

        // Skip the encryption metadata
        byte[] mergedCipherBytes = RepositoryEncryptorUtils.extractCipherBytes(persistedMergedBytes, mergedMetadata)
        CipherInputStream verificationCipherStream = new CipherInputStream(new ByteArrayInputStream(mergedCipherBytes), verificationCipher)

        // Use #bytes rather than #read(byte[]) because read only gets 512 bytes at a time (the internal buffer size)
        byte[] recoveredBytes = verificationCipherStream.bytes
        logger.verify("Decrypted bytes (${recoveredBytes.length}): ${Hex.toHexString(recoveredBytes)} - ${new String(recoveredBytes, StandardCharsets.UTF_8)}")
        assert new String(recoveredBytes, StandardCharsets.UTF_8) == plainContent

        // Use the EFSR to decrypt the original claims content
        claims.eachWithIndex { ContentClaim claim, int i ->
            final InputStream inputStream = repository.read(claim)
            byte[] retrievedContent = inputStream.bytes
            logger.info("Read bytes via repository (${retrievedContent.length}): ${pba(retrievedContent)}")

            // Assert
            assert retrievedContent == content[i].bytes
        }

        // Use the EFSR to decrypt the merged claim content
        final InputStream mergedInputStream = repository.read(mergedClaim)
        byte[] retrievedMergedContent = mergedInputStream.bytes
        logger.info("Read merged bytes via repository (${retrievedMergedContent.length}): ${pba(retrievedMergedContent)}")

        // Assert
        assert retrievedMergedContent == plainBytes
    }

    // TODO: Repeat test with source claims with header, footer, and demarcator to determine if/how they are encrypted
    // TODO: Repeat test with source claims with different keys

    // TODO: Test archiving & cleanup

    private KeyProvider createMockKeyProvider() {
        KeyProvider mockKeyProvider = [
                getKey            : { String keyId ->
                    logger.mock("Requesting key ${keyId}")
                    KEYS[keyId]
                },
                keyExists         : { String keyId ->
                    logger.mock("Checking existence of ${keyId}")
                    KEYS.containsKey(keyId)
                },
                getAvailableKeyIds: { ->
                    logger.mock("Listing available keys")
                    KEYS.keySet() as List
                }
        ] as KeyProvider
        mockKeyProvider
    }

    private String getPersistedFilePath(ContentClaim claim) {
        [rootFile, claim.resourceClaim.section, claim.resourceClaim.id].join(File.separator)
    }

    private static String pba(byte[] bytes, int length = 16) {
        "[${Hex.toHexString(bytes)[0..<(Math.min(length, bytes.length))]}${bytes.length > length ? "..." : ""}]"
    }
}
