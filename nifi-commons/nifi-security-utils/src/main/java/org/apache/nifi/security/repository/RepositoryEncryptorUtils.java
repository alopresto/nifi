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
package org.apache.nifi.security.repository;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.nifi.security.kms.EncryptionException;
import org.apache.nifi.security.util.EncryptionMethod;
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RepositoryEncryptorUtils {
    private static final Logger logger = LoggerFactory.getLogger(RepositoryEncryptorUtils.class);

    private static final int IV_LENGTH = 16;
    private static final byte[] EMPTY_IV = new byte[IV_LENGTH];
    private static final String VERSION = "v1";
    private static final List<String> SUPPORTED_VERSIONS = Arrays.asList(VERSION);
    private static final int MIN_METADATA_LENGTH = IV_LENGTH + 3 + 3; // 3 delimiters and 3 non-zero elements
    private static final int METADATA_DEFAULT_LENGTH = (20 + 17 + IV_LENGTH + VERSION.length()) * 2; // Default to twice the expected length

    public static byte[] serializeEncryptionMetadata(RepositoryObjectEncryptionMetadata metadata) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new ObjectOutputStream(baos);
        outputStream.writeObject(metadata);
        outputStream.close();
        return baos.toByteArray();
    }

    public static Cipher initCipher(AESKeyedCipherProvider aesKeyedCipherProvider, EncryptionMethod method, int mode, SecretKey key, byte[] ivBytes) throws EncryptionException {
        try {
            if (method == null || key == null || ivBytes == null) {
                throw new IllegalArgumentException("Missing critical information");
            }
            return aesKeyedCipherProvider.getCipher(method, key, ivBytes, mode == Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            logger.error("Encountered an exception initializing the cipher", e);
            throw new EncryptionException(e);
        }
    }

    public static RepositoryObjectEncryptionMetadata extractEncryptionMetadata(byte[] encryptedRecord) throws EncryptionException, IOException, ClassNotFoundException {
        // TODO: Inject parser for min metadata length
        if (encryptedRecord == null || encryptedRecord.length < MIN_METADATA_LENGTH) {
            throw new EncryptionException("The encrypted record is too short to contain the metadata");
        }

        // TODO: Inject parser for SENTINEL vs non-SENTINEL
        // Skip the first byte (SENTINEL) and don't need to copy all the serialized record
        ByteArrayInputStream bais = new ByteArrayInputStream(encryptedRecord);
        // bais.read();
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (RepositoryObjectEncryptionMetadata) ois.readObject();
        }
    }

    public static RepositoryObjectEncryptionMetadata extractEncryptionMetadata(InputStream encryptedRecord) throws EncryptionException, IOException, ClassNotFoundException {
        // TODO: Inject parser for min metadata length
        if (encryptedRecord == null) {
            throw new EncryptionException("The encrypted record is too short to contain the metadata");
        }

        // TODO: Inject parser for SENTINEL vs non-SENTINEL
        // Skip the first two bytes (EM_START_SENTINEL) and don't need to copy all the serialized record
        // TODO: May need to seek for EM_START_SENTINEL segment first
        encryptedRecord.read(new byte[2]);
        try (ObjectInputStream ois = new ObjectInputStream(encryptedRecord)) {
            return (RepositoryObjectEncryptionMetadata) ois.readObject();
        }
    }

    public static byte[] extractCipherBytes(byte[] encryptedRecord, RepositoryObjectEncryptionMetadata metadata) {
        return Arrays.copyOfRange(encryptedRecord, encryptedRecord.length - metadata.cipherByteLength, encryptedRecord.length);
    }
}
