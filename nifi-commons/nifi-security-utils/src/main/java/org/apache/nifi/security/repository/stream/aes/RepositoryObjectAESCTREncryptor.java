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
package org.apache.nifi.security.repository.stream.aes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.security.kms.CryptoUtils;
import org.apache.nifi.security.kms.EncryptionException;
import org.apache.nifi.security.kms.KeyProvider;
import org.apache.nifi.security.repository.RepositoryEncryptorUtils;
import org.apache.nifi.security.repository.RepositoryObjectEncryptionMetadata;
import org.apache.nifi.security.repository.StreamingEncryptionMetadata;
import org.apache.nifi.security.repository.stream.RepositoryObjectStreamEncryptor;
import org.apache.nifi.security.util.EncryptionMethod;
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RepositoryObjectAESCTREncryptor implements RepositoryObjectStreamEncryptor {
    private static final Logger logger = LoggerFactory.getLogger(RepositoryObjectAESCTREncryptor.class);
    private static final byte[] EM_START_SENTINEL = new byte[]{0x00, 0x00};
    private static final byte[] EM_END_SENTINEL = new byte[]{(byte) 0xFF, (byte) 0xFF};
    private static String ALGORITHM = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;
    private static final byte[] EMPTY_IV = new byte[IV_LENGTH];
    private static final String VERSION = "v1";
    private static final List<String> SUPPORTED_VERSIONS = Arrays.asList(VERSION);
    private static final int MIN_METADATA_LENGTH = IV_LENGTH + 3 + 3; // 3 delimiters and 3 non-zero elements
    private static final int METADATA_DEFAULT_LENGTH = (20 + ALGORITHM.length() + IV_LENGTH + VERSION.length()) * 2; // Default to twice the expected length

    private KeyProvider keyProvider;

    private AESKeyedCipherProvider aesKeyedCipherProvider = new AESKeyedCipherProvider();

    /**
     * Initializes the encryptor with a {@link KeyProvider}.
     *
     * @param keyProvider the key provider which will be responsible for accessing keys
     * @throws KeyManagementException if there is an issue configuring the key provider
     */
    @Override
    public void initialize(KeyProvider keyProvider) throws KeyManagementException {
        this.keyProvider = keyProvider;

        if (this.aesKeyedCipherProvider == null) {
            this.aesKeyedCipherProvider = new AESKeyedCipherProvider();
        }

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Available for dependency injection to override the default {@link AESKeyedCipherProvider} if necessary.
     *
     * @param cipherProvider the AES cipher provider to use
     */
    void setCipherProvider(AESKeyedCipherProvider cipherProvider) {
        this.aesKeyedCipherProvider = cipherProvider;
    }

    /**
     * Encrypts the serialized byte[].
     *
     * @param plainRecord the plain record, serialized to a byte[]
     * @param recordId    an identifier for this record (eventId, generated, etc.)
     * @param keyId       the ID of the key to use
     * @return the encrypted record
     * @throws EncryptionException if there is an issue encrypting this record
     */
    @Override
    public OutputStream encrypt(OutputStream plainRecord, String recordId, String keyId) throws EncryptionException {
        if (plainRecord == null || CryptoUtils.isEmpty(keyId)) {
            throw new EncryptionException("The provenance record and key ID cannot be missing");
        }

        if (keyProvider == null || !keyProvider.keyExists(keyId)) {
            throw new EncryptionException("The requested key ID is not available");
        } else {
            byte[] ivBytes = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(ivBytes);
            try {
                logger.debug("Encrypting provenance record " + recordId + " with key ID " + keyId);
                Cipher cipher = RepositoryEncryptorUtils.initCipher(aesKeyedCipherProvider, EncryptionMethod.AES_GCM, Cipher.ENCRYPT_MODE, keyProvider.getKey(keyId), ivBytes);
                ivBytes = cipher.getIV();

                // Prepare the output stream for the actual encryption
                CipherOutputStream cipherOutputStream = new CipherOutputStream(plainRecord, cipher);

                // Serialize and concat encryption details fields (keyId, algo, IV, version, CB length) outside of encryption
                RepositoryObjectEncryptionMetadata metadata = new StreamingEncryptionMetadata(keyId, ALGORITHM, ivBytes, VERSION);
                byte[] serializedEncryptionMetadata = RepositoryEncryptorUtils.serializeEncryptionMetadata(metadata);

                // Write the SENTINEL bytes and the encryption metadata to the raw output stream
                plainRecord.write(EM_START_SENTINEL);
                plainRecord.write(serializedEncryptionMetadata);
                // plainRecord.write(EM_END_SENTINEL);

                logger.debug("Encrypted streaming repository object " + recordId + " with key ID " + keyId);
                return cipherOutputStream;
            } catch (EncryptionException | IOException | KeyManagementException e) {
                final String msg = "Encountered an exception encrypting streaming repository object " + recordId;
                logger.error(msg, e);
                throw new EncryptionException(msg, e);
            }
        }
    }

    /**
     * Decrypts the provided byte[] (an encrypted record with accompanying metadata).
     *
     * @param encryptedRecord the encrypted record in byte[] form
     * @param recordId        an identifier for this record (eventId, generated, etc.)
     * @return the decrypted record
     * @throws EncryptionException if there is an issue decrypting this record
     */
    @Override
    public InputStream decrypt(InputStream encryptedRecord, String recordId) throws EncryptionException {
        if (encryptedRecord == null) {
            throw new EncryptionException("The encrypted provenance record cannot be missing");
        }

        RepositoryObjectEncryptionMetadata metadata;
        try {
            metadata = RepositoryEncryptorUtils.extractEncryptionMetadata(encryptedRecord);
        } catch (IOException | ClassNotFoundException e) {
            final String msg = "Encountered an error reading the encryption metadata: ";
            logger.error(msg, e);
            throw new EncryptionException(msg, e);
        }

        if (!SUPPORTED_VERSIONS.contains(metadata.version)) {
            throw new EncryptionException("The event was encrypted with version " + metadata.version + " which is not in the list of supported versions " + StringUtils.join(SUPPORTED_VERSIONS, ","));
        }

        // TODO: Actually use the version to determine schema, etc.

        if (keyProvider == null || !keyProvider.keyExists(metadata.keyId) || CryptoUtils.isEmpty(metadata.keyId)) {
            throw new EncryptionException("The requested key ID " + metadata.keyId + " is not available");
        } else {
            try {
                logger.debug("Decrypting provenance record " + recordId + " with key ID " + metadata.keyId);
                EncryptionMethod method = EncryptionMethod.forAlgorithm(metadata.algorithm);
                Cipher cipher = RepositoryEncryptorUtils.initCipher(aesKeyedCipherProvider, method, Cipher.DECRYPT_MODE, keyProvider.getKey(metadata.keyId), metadata.ivBytes);

                // Return a new CipherInputStream wrapping the encrypted stream at the present location
                CipherInputStream cipherInputStream = new CipherInputStream(encryptedRecord, cipher);

                logger.debug("Decrypted provenance event record " + recordId + " with key ID " + metadata.keyId);
                return cipherInputStream;
            } catch (EncryptionException | KeyManagementException e) {
                final String msg = "Encountered an exception decrypting provenance record " + recordId;
                logger.error(msg, e);
                throw new EncryptionException(msg, e);
            }
        }
    }

    /**
     * Returns a valid key identifier for this encryptor (valid for encryption and decryption) or throws an exception if none are available.
     *
     * @return the key ID
     * @throws KeyManagementException if no available key IDs are valid for both operations
     */
    @Override
    public String getNextKeyId() throws KeyManagementException {
        return null;
    }
}
