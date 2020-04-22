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
package org.apache.nifi.security.util.crypto;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.StreamCallback;
import org.apache.nifi.processors.standard.EncryptContent;
import org.apache.nifi.security.util.EncryptionMethod;
import org.apache.nifi.security.util.KeyDerivationFunction;
import org.apache.nifi.stream.io.ByteCountingInputStream;
import org.apache.nifi.stream.io.ByteCountingOutputStream;

public class PasswordBasedEncryptor extends AbstractEncryptor {

    private EncryptionMethod encryptionMethod;
    private PBEKeySpec password;
    private KeyDerivationFunction kdf;

    private static final int DEFAULT_MAX_ALLOWED_KEY_LENGTH = 128;
    private static final int MINIMUM_SAFE_PASSWORD_LENGTH = 10;

    public PasswordBasedEncryptor(final EncryptionMethod encryptionMethod, final char[] password, KeyDerivationFunction kdf) {
        super();
        try {
            if (encryptionMethod == null) {
                throw new IllegalArgumentException("Cannot initialize password-based encryptor with null encryption method");
            }
            this.encryptionMethod = encryptionMethod;
            if (kdf == null || kdf.equals(KeyDerivationFunction.NONE)) {
                throw new IllegalArgumentException("Cannot initialize password-based encryptor with null KDF");
            }
            this.kdf = kdf;
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Cannot initialize password-based encryptor with empty password");
            }
            this.password = new PBEKeySpec(password);
        } catch (Exception e) {
            throw new ProcessException(e);
        }
    }

    public static int getMaxAllowedKeyLength(final String algorithm) {
        if (StringUtils.isEmpty(algorithm)) {
            return DEFAULT_MAX_ALLOWED_KEY_LENGTH;
        }
        String parsedCipher = CipherUtility.parseCipherFromAlgorithm(algorithm);
        try {
            return Cipher.getMaxAllowedKeyLength(parsedCipher);
        } catch (NoSuchAlgorithmException e) {
            // Default algorithm max key length on unmodified JRE
            return DEFAULT_MAX_ALLOWED_KEY_LENGTH;
        }
    }

    /**
     * Returns a recommended minimum length for passwords. This can be modified over time and does not take full entropy calculations (patterns, character space, etc.) into account.
     *
     * @return the minimum safe password length
     */
    public static int getMinimumSafePasswordLength() {
        return MINIMUM_SAFE_PASSWORD_LENGTH;
    }

    static Map<String, String> writeAttributes(EncryptionMethod encryptionMethod,
                                               KeyDerivationFunction kdf, byte[] iv, byte[] kdfSalt, ByteCountingInputStream bcis, ByteCountingOutputStream bcos, boolean encryptMode) {
        Map<String, String> attributes = AbstractEncryptor.writeAttributes(encryptionMethod, kdf, iv, bcis, bcos, encryptMode);

        if (kdf.hasFormattedSalt()) {
            final String saltString = new String(kdfSalt, StandardCharsets.UTF_8);
            attributes.put(EncryptContent.KDF_SALT_ATTR, saltString);
            attributes.put(EncryptContent.KDF_SALT_LEN_ATTR, String.valueOf(saltString.length()));
        }

        byte[] rawSalt = CipherUtility.extractRawSalt(kdfSalt, kdf);
        attributes.put(EncryptContent.SALT_ATTR, Hex.encodeHexString(rawSalt));
        attributes.put(EncryptContent.SALT_LEN_ATTR, String.valueOf(rawSalt.length));

        return attributes;
    }

    @Override
    public StreamCallback getEncryptionCallback() throws ProcessException {
        return new EncryptCallback();
    }

    @Override
    public StreamCallback getDecryptionCallback() throws ProcessException {
        return new DecryptCallback();
    }

    @SuppressWarnings("deprecation")
    private class DecryptCallback implements StreamCallback {

        private static final boolean DECRYPT = false;

        public DecryptCallback() {
        }

        @Override
        public void process(final InputStream in, final OutputStream out) throws IOException {
            // Initialize cipher provider
            PBECipherProvider cipherProvider = (PBECipherProvider) CipherProviderFactory.getCipherProvider(kdf);

            // Wrap the streams for byte counting if necessary
            ByteCountingInputStream bcis = CipherUtility.wrapStreamForCounting(in);
            ByteCountingOutputStream bcos = CipherUtility.wrapStreamForCounting(out);

            // Read salt
            byte[] salt;
            try {
                // NiFi legacy code determined the salt length based on the cipher block size
                if (cipherProvider instanceof org.apache.nifi.security.util.crypto.NiFiLegacyCipherProvider) {
                    salt = ((org.apache.nifi.security.util.crypto.NiFiLegacyCipherProvider) cipherProvider).readSalt(encryptionMethod, bcis);
                } else {
                    salt = cipherProvider.readSalt(bcis);
                }
            } catch (final EOFException e) {
                throw new ProcessException("Cannot decrypt because file size is smaller than salt size", e);
            }

            // Determine necessary key length
            int keyLength = CipherUtility.parseKeyLengthFromAlgorithm(encryptionMethod.getAlgorithm());

            // Generate cipher
            try {
                Cipher cipher;
                // Read IV if necessary
                if (cipherProvider instanceof RandomIVPBECipherProvider) {
                    RandomIVPBECipherProvider rivpcp = (RandomIVPBECipherProvider) cipherProvider;
                    byte[] iv = rivpcp.readIV(bcis);
                    cipher = rivpcp.getCipher(encryptionMethod, new String(password.getPassword()), salt, iv, keyLength, DECRYPT);
                } else {
                    cipher = cipherProvider.getCipher(encryptionMethod, new String(password.getPassword()), salt, keyLength, DECRYPT);
                }
                CipherUtility.processStreams(cipher, bcis, bcos);

                // Update the attributes in the temporary holder
                flowfileAttributes = writeAttributes(encryptionMethod, kdf, cipher.getIV(), salt, bcis, bcos, DECRYPT);
            } catch (Exception e) {
                throw new ProcessException(e);
            }
        }
    }

    @SuppressWarnings("deprecation")
    private class EncryptCallback implements StreamCallback {

        private static final boolean ENCRYPT = true;

        public EncryptCallback() {
        }

        @Override
        public void process(final InputStream in, final OutputStream out) throws IOException {
            // Initialize cipher provider
            PBECipherProvider cipherProvider = (PBECipherProvider) CipherProviderFactory.getCipherProvider(kdf);

            // Generate salt
            byte[] salt;
            // NiFi legacy code determined the salt length based on the cipher block size
            if (cipherProvider instanceof org.apache.nifi.security.util.crypto.NiFiLegacyCipherProvider) {
                salt = ((org.apache.nifi.security.util.crypto.NiFiLegacyCipherProvider) cipherProvider).generateSalt(encryptionMethod);
            } else {
                salt = cipherProvider.generateSalt();
            }

            // Wrap the streams for byte counting if necessary
            ByteCountingInputStream bcis = CipherUtility.wrapStreamForCounting(in);
            ByteCountingOutputStream bcos = CipherUtility.wrapStreamForCounting(out);

            // Write to output stream
            cipherProvider.writeSalt(salt, bcos);

            // Determine necessary key length
            int keyLength = CipherUtility.parseKeyLengthFromAlgorithm(encryptionMethod.getAlgorithm());

            // Generate cipher
            try {
                Cipher cipher = cipherProvider.getCipher(encryptionMethod, new String(password.getPassword()), salt, keyLength, ENCRYPT);

                // Write IV if necessary
                if (cipherProvider instanceof RandomIVPBECipherProvider) {
                    ((RandomIVPBECipherProvider) cipherProvider).writeIV(cipher.getIV(), bcos);
                }
                CipherUtility.processStreams(cipher, bcis, bcos);

                // Update the attributes in the temporary holder
                flowfileAttributes = writeAttributes(encryptionMethod, kdf, cipher.getIV(), salt, bcis, bcos, ENCRYPT);
            } catch (Exception e) {
                throw new ProcessException(e);
            }
        }
    }
}