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

import java.security.KeyManagementException;
import java.security.Security;
import org.apache.nifi.security.kms.KeyProvider;
import org.apache.nifi.security.util.crypto.AESKeyedCipherProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAESEncryptor implements RepositoryObjectEncryptor {
    private static final Logger logger = LoggerFactory.getLogger(AbstractAESEncryptor.class);
    private static final byte[] EM_START_SENTINEL = new byte[]{0x00, 0x00};
    private static final byte[] EM_END_SENTINEL = new byte[]{(byte) 0xFF, (byte) 0xFF};
    private static String ALGORITHM = "AES/CTR/NoPadding";
    protected static final int IV_LENGTH = 16;
    protected static final byte[] EMPTY_IV = new byte[IV_LENGTH];
    // private static final String VERSION = "v1";
    // private static final List<String> SUPPORTED_VERSIONS = Arrays.asList(VERSION);

    protected KeyProvider keyProvider;

    protected AESKeyedCipherProvider aesKeyedCipherProvider = new AESKeyedCipherProvider();

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
}
