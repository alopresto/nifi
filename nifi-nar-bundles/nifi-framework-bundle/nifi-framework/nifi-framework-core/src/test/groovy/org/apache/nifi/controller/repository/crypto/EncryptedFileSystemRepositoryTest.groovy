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
            (NiFiProperties.CONTENT_REPOSITORY_IMPLEMENTATION): "org.apache.nifi.controller.repository.crypto.EncryptedFileSystemRepository",
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_ID): KEY_ID_1,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY): KEY_HEX_1,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_PROVIDER_IMPLEMENTATION_CLASS): StaticKeyProvider.class.name,
            (NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_PROVIDER_LOCATION): ""
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
            logger.info("Read bytes via repository (${retrievedContent.length}): ${Hex.toHexString(retrievedContent)}")

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
            logger.verify("Read bytes (${persistedBytes.length}): ${Hex.toHexString(persistedBytes)}")

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
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${Hex.toHexString(plainBytes)}")

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
        logger.info("Writing \"${plainContent}\" (${plainContent.length()}): ${Hex.toHexString(plainBytes)}")

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
        logger.info("Read bytes via repository (${retrievedContent.length}): ${Hex.toHexString(retrievedContent)}")

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
}
