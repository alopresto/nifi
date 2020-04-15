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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.StreamCallback;
import org.apache.nifi.processors.standard.EncryptContent;
import org.apache.nifi.processors.standard.EncryptContent.Encryptor;
import org.apache.nifi.security.util.EncryptionMethod;
import org.apache.nifi.security.util.KeyDerivationFunction;
import org.apache.nifi.stream.io.ByteCountingInputStream;
import org.apache.nifi.stream.io.ByteCountingOutputStream;

public class KeyedEncryptor implements Encryptor {

    private EncryptionMethod encryptionMethod;
    private SecretKey key;
    private byte[] iv;

    private transient Map<String, String> flowfileAttributes = new HashMap<>();

    private static final int DEFAULT_MAX_ALLOWED_KEY_LENGTH = 128;

    private static boolean isUnlimitedStrengthCryptographyEnabled;

    // Evaluate an unlimited strength algorithm to determine if we support the capability we have on the system
    static {
        try {
            isUnlimitedStrengthCryptographyEnabled = (Cipher.getMaxAllowedKeyLength("AES") > DEFAULT_MAX_ALLOWED_KEY_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            // if there are issues with this, we default back to the value established
            isUnlimitedStrengthCryptographyEnabled = false;
        }
    }

    public KeyedEncryptor(final EncryptionMethod encryptionMethod, final SecretKey key) {
        this(encryptionMethod, key == null ? new byte[0] : key.getEncoded(), new byte[0]);
    }

    public KeyedEncryptor(final EncryptionMethod encryptionMethod, final SecretKey key, final byte[] iv) {
        this(encryptionMethod, key == null ? new byte[0] : key.getEncoded(), iv);
    }

    public KeyedEncryptor(final EncryptionMethod encryptionMethod, final byte[] keyBytes) {
        this(encryptionMethod, keyBytes, new byte[0]);
    }

    public KeyedEncryptor(final EncryptionMethod encryptionMethod, final byte[] keyBytes, final byte[] iv) {
        super();
        try {
            if (encryptionMethod == null) {
                throw new IllegalArgumentException("Cannot instantiate a keyed encryptor with null encryption method");
            }
            if (!encryptionMethod.isKeyedCipher()) {
                throw new IllegalArgumentException("Cannot instantiate a keyed encryptor with encryption method " + encryptionMethod.name());
            }
            this.encryptionMethod = encryptionMethod;
            if (keyBytes == null || keyBytes.length == 0) {
                throw new IllegalArgumentException("Cannot instantiate a keyed encryptor with empty key");
            }
            if (!CipherUtility.isValidKeyLengthForAlgorithm(keyBytes.length * 8, encryptionMethod.getAlgorithm())) {
                throw new IllegalArgumentException("Cannot instantiate a keyed encryptor with key of length " + keyBytes.length);
            }
            String cipherName = CipherUtility.parseCipherFromAlgorithm(encryptionMethod.getAlgorithm());
            this.key = new SecretKeySpec(keyBytes, cipherName);

            this.iv = iv;
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

    public static boolean supportsUnlimitedStrength() {
        return isUnlimitedStrengthCryptographyEnabled;
    }

    @Override
    public void updateAttributes(Map<String, String> attributes) throws ProcessException {
        if (attributes == null) {
            throw new IllegalArgumentException("Cannot update null flowfile attributes");
        }

        attributes.putAll(flowfileAttributes);
    }

    static Map<String, String> writeAttributes(EncryptionMethod encryptionMethod, KeyDerivationFunction kdf, byte[] iv, ByteCountingInputStream bcis, ByteCountingOutputStream bcos, boolean encryptMode) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put(EncryptContent.ACTION_ATTR, encryptMode ? "encrypted" : "decrypted");
        attributes.put(EncryptContent.ALGORITHM_ATTR, encryptionMethod.name());
        attributes.put(EncryptContent.KDF_ATTR, kdf.name());
        attributes.put(EncryptContent.TS_ATTR, CipherUtility.getTimestampString());
        attributes.put(EncryptContent.IV_ATTR, Hex.encodeHexString(iv));
        attributes.put(EncryptContent.IV_LEN_ATTR, String.valueOf(iv.length));

        // If encrypting, the plaintext is the input and the cipher text is the output
        if (encryptMode) {
            attributes.put(EncryptContent.PT_LEN_ATTR, String.valueOf(bcis.getBytesRead()));
            attributes.put(EncryptContent.CT_LEN_ATTR, String.valueOf(bcos.getBytesWritten()));
        } else {
            // If decrypting, switch the streams
            attributes.put(EncryptContent.PT_LEN_ATTR, String.valueOf(bcos.getBytesWritten()));
            attributes.put(EncryptContent.CT_LEN_ATTR, String.valueOf(bcis.getBytesRead()));
        }
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

    private class DecryptCallback implements StreamCallback {

        public DecryptCallback() {
        }

        @Override
        public void process(final InputStream in, final OutputStream out) throws IOException {
            // Initialize cipher provider
            KeyedCipherProvider cipherProvider = (KeyedCipherProvider) CipherProviderFactory.getCipherProvider(KeyDerivationFunction.NONE);

            // Wrap the streams for byte counting if necessary
            ByteCountingInputStream bcis = CipherUtility.wrapStreamForCounting(in);
            ByteCountingOutputStream bcos = CipherUtility.wrapStreamForCounting(out);

            // Generate cipher
            Cipher cipher;
            try {
                // The IV could have been set by the constructor, but if not, read from the cipher stream
                if (iv.length == 0) {
                    iv = cipherProvider.readIV(bcis);
                }
                cipher = cipherProvider.getCipher(encryptionMethod, key, iv, false);
                CipherUtility.processStreams(cipher, bcis, bcos);
            } catch (Exception e) {
                throw new ProcessException(e);
            }

            // Update the attributes in the temporary holder
            flowfileAttributes = writeAttributes(encryptionMethod, KeyDerivationFunction.NONE, iv, bcis, bcos, false);
        }
    }

    private class EncryptCallback implements StreamCallback {

        public EncryptCallback() {
        }

        @Override
        public void process(final InputStream in, final OutputStream out) throws IOException {
            // Initialize cipher provider
            KeyedCipherProvider cipherProvider = (KeyedCipherProvider) CipherProviderFactory.getCipherProvider(KeyDerivationFunction.NONE);

            // Wrap the streams for byte counting if necessary
            ByteCountingInputStream bcis = CipherUtility.wrapStreamForCounting(in);
            ByteCountingOutputStream bcos = CipherUtility.wrapStreamForCounting(out);

            // Generate cipher
            Cipher cipher;
            try {
                cipher = cipherProvider.getCipher(encryptionMethod, key, iv, true);
                cipherProvider.writeIV(cipher.getIV(), bcos);
                CipherUtility.processStreams(cipher, bcis, bcos);
            } catch (Exception e) {
                throw new ProcessException(e);
            }

            // Update the attributes in the temporary holder
            flowfileAttributes = writeAttributes(encryptionMethod, KeyDerivationFunction.NONE, cipher.getIV(), bcis, bcos, true);
        }
    }
}