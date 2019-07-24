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
package org.apache.nifi.controller.repository.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.controller.repository.FileSystemRepository;
import org.apache.nifi.controller.repository.claim.ContentClaim;
import org.apache.nifi.controller.repository.claim.StandardContentClaim;
import org.apache.nifi.security.kms.CryptoUtils;
import org.apache.nifi.security.kms.EncryptionException;
import org.apache.nifi.security.kms.KeyProvider;
import org.apache.nifi.security.kms.KeyProviderFactory;
import org.apache.nifi.security.repository.RepositoryType;
import org.apache.nifi.security.repository.config.RepositoryEncryptionConfiguration;
import org.apache.nifi.security.repository.stream.RepositoryObjectStreamEncryptor;
import org.apache.nifi.security.repository.stream.aes.RepositoryObjectAESCTREncryptor;
import org.apache.nifi.stream.io.ByteCountingOutputStream;
import org.apache.nifi.stream.io.NonCloseableOutputStream;
import org.apache.nifi.util.NiFiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptedFileSystemRepository extends FileSystemRepository {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedFileSystemRepository.class);

    private String activeKeyId;
    private KeyProvider keyProvider;

    /**
     * Default no args constructor for service loading only
     */
    public EncryptedFileSystemRepository() {
        super();
        keyProvider = null;
    }

    public EncryptedFileSystemRepository(final NiFiProperties niFiProperties) throws IOException {
        super(niFiProperties);

        // Initialize key provider
        initializeEncryptionServices(niFiProperties);
    }

    private void initializeEncryptionServices(NiFiProperties niFiProperties) throws IOException {
        // Initialize the encryption-specific fields
        if (CryptoUtils.isContentRepositoryEncryptionConfigured(niFiProperties)) {
            try {
                KeyProvider keyProvider;
                final String keyProviderImplementation = niFiProperties.getProperty(NiFiProperties.CONTENT_REPOSITORY_ENCRYPTION_KEY_PROVIDER_IMPLEMENTATION_CLASS);
                if (KeyProviderFactory.requiresMasterKey(keyProviderImplementation)) {
                    SecretKey masterKey = CryptoUtils.getMasterKey();
                    keyProvider = buildKeyProvider(niFiProperties, masterKey);
                } else {
                    keyProvider = buildKeyProvider(niFiProperties);
                }
                this.keyProvider = keyProvider;
            } catch (KeyManagementException e) {
                String msg = "Encountered an error building the key provider";
                logger.error(msg, e);
                throw new IOException(msg, e);
            }
        } else {
            throw new IOException("The provided configuration does not support a encrypted repository");
        }
        // Set active key ID
        setActiveKeyId(niFiProperties.getContentRepositoryEncryptionKeyId());
    }

    /**
     * Returns a configured {@link KeyProvider} instance that does not require a {@code master key} to use (usually a {@link org.apache.nifi.security.kms.StaticKeyProvider}).
     *
     * @param niFiProperties the {@link NiFiProperties} object
     * @return the configured KeyProvider
     * @throws KeyManagementException if there is a problem with the configuration
     */
    private static KeyProvider buildKeyProvider(NiFiProperties niFiProperties) throws KeyManagementException {
        return buildKeyProvider(niFiProperties, null);
    }

    /**
     * Returns a configured {@link KeyProvider} instance that requires a {@code master key} to use
     * (usually a {@link org.apache.nifi.security.kms.FileBasedKeyProvider} or an encrypted
     * {@link org.apache.nifi.security.kms.StaticKeyProvider}).
     *
     * @param niFiProperties the {@link NiFiProperties} object
     * @param masterKey      the master encryption key used to encrypt the data encryption keys in the key provider configuration
     * @return the configured KeyProvider
     * @throws KeyManagementException if there is a problem with the configuration
     */
    private static KeyProvider buildKeyProvider(NiFiProperties niFiProperties, SecretKey masterKey) throws KeyManagementException {
        return KeyProviderFactory.buildKeyProvider(RepositoryEncryptionConfiguration.fromNiFiProperties(niFiProperties, RepositoryType.CONTENT), masterKey);
    }

    @Override
    public InputStream read(final ContentClaim claim) throws IOException {
        InputStream inputStream = super.read(claim);

        try {
            String recordId = getRecordId(claim);
            logger.debug("Creating decrypted input stream to read flowfile content with record ID: " + recordId);

            final InputStream decryptingInputStream = getDecryptingInputStream(inputStream, recordId);
            logger.debug("Reading from record ID {}", recordId);
            if (logger.isTraceEnabled()) {
                logger.trace("Stack trace: ", new RuntimeException("Stack Trace for reading from record ID " + recordId));
            }

            return decryptingInputStream;
        } catch (EncryptionException | KeyManagementException e) {
            logger.error("Encountered an error instantiating the encrypted content repository input stream: " + e.getMessage());
            throw new IOException("Error creating encrypted content repository input stream", e);
        }
    }

    private InputStream getDecryptingInputStream(InputStream inputStream, String recordId) throws KeyManagementException, EncryptionException {
        RepositoryObjectStreamEncryptor encryptor = new RepositoryObjectAESCTREncryptor();
        encryptor.initialize(keyProvider);

        // ECROS wrapping COS wrapping BCOS wrapping FOS
        return encryptor.decrypt(inputStream, recordId);
    }

    @Override
    public OutputStream write(final ContentClaim claim) throws IOException {
        return write(claim, false);
    }

    private OutputStream write(final ContentClaim claim, final boolean append) throws IOException {
        StandardContentClaim scc = validateContentClaimForWriting(claim);

        // BCOS wrapping FOS
        ByteCountingOutputStream claimStream = getWritableClaimStreamByResourceClaim(scc.getResourceClaim());
        final long startingOffset = claimStream.getBytesWritten();

        try {
            String keyId = getActiveKeyId();
            String recordId = getRecordId(claim);
            logger.debug("Creating encrypted output stream (keyId: " + keyId + ") to write flowfile content with record ID: " + recordId);
            final OutputStream out = getEncryptedOutputStream(scc, claimStream, startingOffset, keyId, recordId);
            logger.debug("Writing to {}", out);
            if (logger.isTraceEnabled()) {
                logger.trace("Stack trace: ", new RuntimeException("Stack Trace for writing to " + out));
            }

            return out;
        } catch (EncryptionException | KeyManagementException e) {
            logger.error("Encountered an error instantiating the encrypted content repository output stream: " + e.getMessage());
            throw new IOException("Error creating encrypted content repository output stream", e);
        }
    }

    String getActiveKeyId() {
        return activeKeyId;
    }

    public void setActiveKeyId(String activeKeyId) {
        // Key must not be blank and key provider must make key available
        if (StringUtils.isNotBlank(activeKeyId) && keyProvider.keyExists(activeKeyId)) {
            this.activeKeyId = activeKeyId;
            logger.debug("Set active key ID to '" + activeKeyId + "'");
        } else {
            logger.warn("Attempted to set active key ID to '" + activeKeyId + "' but that is not a valid or available key ID. Keeping active key ID as '" + this.activeKeyId + "'");

        }
    }

    /**
     * Returns an identifier for this {@link ContentClaim} to be used when serializing/retrieving the encrypted content.
     * For version 1, the identifier is {@code "nifi-ecr-rc-" + the resource claim ID + offset}. If any piece of the
     * CC -> RC -> ID chain is null or empty, the current system time in nanoseconds is used with a different
     * prefix ({@code "nifi-ecr-ts-"}).
     *
     * @param claim the content claim
     * @return the string identifier
     */
    public static String getRecordId(ContentClaim claim) {
        // For version 1, use the content claim's resource claim ID as the record ID rather than introducing a new field in the metadata
        if (claim != null && claim.getResourceClaim() != null
                && !StringUtils.isBlank(claim.getResourceClaim().getId())) {
            return "nifi-ecr-rc-" + claim.getResourceClaim().getId() + "+" + claim.getOffset();
        } else {
            String tempId = "nifi-ecr-ts-" + System.nanoTime();
            logger.error("Cannot determine record ID from null content claim or claim with missing/empty resource claim ID; using timestamp-generated ID: " + tempId + "+0");
            return tempId;
        }
    }

    private OutputStream getEncryptedOutputStream(StandardContentClaim scc,
                                                  ByteCountingOutputStream claimStream,
                                                  long startingOffset,
                                                  String keyId,
                                                  String recordId) throws KeyManagementException,
            EncryptionException {
        RepositoryObjectStreamEncryptor encryptor = new RepositoryObjectAESCTREncryptor();
        encryptor.initialize(keyProvider);

        // ECROS wrapping COS wrapping BCOS wrapping FOS
        return new EncryptedContentRepositoryOutputStream(scc, claimStream, encryptor, recordId, keyId, startingOffset);
    }

    /**
     * Private class which wraps the {@link org.apache.nifi.controller.repository.FileSystemRepository.ContentRepositoryOutputStream}'s
     * internal {@link ByteCountingOutputStream} with a {@link CipherOutputStream}
     * to handle streaming encryption operations.
     */
    private class EncryptedContentRepositoryOutputStream extends ContentRepositoryOutputStream {
        private final CipherOutputStream cipherOutputStream;
        private final long startingOffset;

        EncryptedContentRepositoryOutputStream(StandardContentClaim scc,
                                                      ByteCountingOutputStream byteCountingOutputStream,
                                                      RepositoryObjectStreamEncryptor encryptor, String recordId, String keyId, long startingOffset) throws EncryptionException {
            super(scc, byteCountingOutputStream, 0);
            this.startingOffset = startingOffset;

            // Set up cipher stream
            this.cipherOutputStream = (CipherOutputStream) encryptor.encrypt(new NonCloseableOutputStream(byteCountingOutputStream), recordId, keyId);
        }

        @Override
        public String toString() {
            return "EncryptedFileSystemRepository Stream [" + scc + "]";
        }

        @Override
        public synchronized void write(final int b) throws IOException {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(b);
            writeBytes(bb.array(), 0, 4);

            scc.setLength(bcos.getBytesWritten() - startingOffset);
        }

        @Override
        public synchronized void write(final byte[] b) throws IOException {
            writeBytes(b, 0, b.length);

            scc.setLength(bcos.getBytesWritten() - startingOffset);
        }

        @Override
        public synchronized void write(final byte[] b, final int off, final int len) throws IOException {
            writeBytes(b, off, len);

            scc.setLength(bcos.getBytesWritten() - startingOffset);
        }

        /**
         * Internal method used to reduce duplication throughout code.
         *
         * @param b the byte array to write
         * @param off the offset in bytes
         * @param len the length in bytes to write
         * @throws IOException if there is a problem writing the output
         */
        private void writeBytes(byte[] b, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("Stream is closed");
            }

            try {
                cipherOutputStream.write(b, off, len);
            } catch (final IOException ioe) {
                recycle = false;
                throw new IOException("Failed to write to " + this, ioe);
            }
        }

        @Override
        public synchronized void flush() throws IOException {
            if (closed) {
                throw new IOException("Stream is closed");
            }

            cipherOutputStream.flush();
        }

        @Override
        public synchronized void close() throws IOException {
            closed = true;

            // Always flush and close (close triggers cipher.doFinal())
            cipherOutputStream.flush();
            cipherOutputStream.close();

            // Add the additional bytes written to the scc.length
            scc.setLength(bcos.getBytesWritten() - startingOffset);

            super.close();
        }
    }
}
