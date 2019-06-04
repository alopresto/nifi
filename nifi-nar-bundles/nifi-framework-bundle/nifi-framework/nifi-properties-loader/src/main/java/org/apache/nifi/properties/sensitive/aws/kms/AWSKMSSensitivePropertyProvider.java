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
package org.apache.nifi.properties.sensitive.aws.kms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.GenerateRandomRequest;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.properties.sensitive.SensitivePropertyMetadata;
import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AWSKMSSensitivePropertyProvider implements SensitivePropertyProvider {
    private static final Logger logger = LoggerFactory.getLogger(AWSKMSSensitivePropertyProvider.class);

    private static final String IMPLEMENTATION_NAME = "AWS KMS Sensitive Property Provider";
    private static final String IMPLEMENTATION_KEY = "aws/kms/"; // .protected=aws/kms/some-key-id-goes-here // follow-on ticket for ConfigEncryption toolkit

    private AWSKMS client;
    private final String key;

    public AWSKMSSensitivePropertyProvider(String keyId) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        this.key = validateKey(keyId);
        this.client = AWSKMSClientBuilder.standard().build();
    }

    private String validateKey(String keyId) {
        if (keyId == null || StringUtils.isBlank(keyId)) {
            throw new SensitivePropertyProtectionException("The key cannot be empty");
        }
        return keyId;
    }

    /**
     * Returns the name of the underlying implementation.
     *
     * @return the name of this sensitive property provider
     */
    @Override
    public String getName() {
        return IMPLEMENTATION_NAME;

    }

    /**
     * Returns the key used to identify the provider implementation in {@code nifi.properties}.
     *
     * @return the key to persist in the sibling property
     */
    @Override
    public String getIdentifierKey() {
        return IMPLEMENTATION_KEY + key; // getIdentifierKey() has to include the kms key id/alias/arn
    }
    

    /**
     * Returns the encrypted cipher text.
     *
     * @param unprotectedValue the sensitive value
     * @return the value to persist in the {@code nifi.properties} file
     * @throws SensitivePropertyProtectionException if there is an exception encrypting the value
     */
    @Override
    public String protect(String unprotectedValue) throws SensitivePropertyProtectionException {
        if (unprotectedValue == null || unprotectedValue.trim().length() == 0) {
            throw new IllegalArgumentException("Cannot encrypt an empty value");
        }

        // TODO: Standardize on explicit character encoding UTF-8
        EncryptRequest request = new EncryptRequest()
            .withKeyId(key)
            .withPlaintext(ByteBuffer.wrap(unprotectedValue.getBytes()));

        EncryptResult response = client.encrypt(request);
        // TODO: Base64 will be more concise here
        return Hex.toHexString(response.getCiphertextBlob().array());
    }

    /**
     * Returns the "protected" form of this value. This is a form which can safely be persisted in the {@code nifi.properties} file without compromising the value.
     * An encryption-based provider would return a cipher text, while a remote-lookup provider could return a unique ID to retrieve the secured value.
     *
     * @param unprotectedValue the sensitive value
     * @param metadata         per-value metadata necessary to perform the protection
     * @return the value to persist in the {@code nifi.properties} file
     */
    @Override
    public String protect(String unprotectedValue, SensitivePropertyMetadata metadata) throws SensitivePropertyProtectionException {
        // TODO: Implement
        return null;
    }

    /**
     * Returns the decrypted plaintext.
     *
     * @param protectedValue the cipher text read from the {@code nifi.properties} file
     * @return the raw value to be used by the application
     * @throws SensitivePropertyProtectionException if there is an error decrypting the cipher text
     */
    @Override
    public String unprotect(String protectedValue) throws SensitivePropertyProtectionException {
        // TODO: Base64 is smaller than hex and should be consistent with the protected value
        DecryptRequest request = new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(Hex.decode(protectedValue)));
                                
        DecryptResult response = client.decrypt(request);
        return new String(response.getPlaintext().array());
    }

    /**
     * Returns the "unprotected" form of this value. This is the raw sensitive value which is used by the application logic.
     * An encryption-based provider would decrypt a cipher text and return the plaintext, while a remote-lookup provider could retrieve the secured value.
     *
     * @param protectedValue the protected value read from the {@code nifi.properties} file
     * @param metadata       per-value metadata necessary to perform the unprotection
     * @return the raw value to be used by the application
     */
    @Override
    public String unprotect(String protectedValue, SensitivePropertyMetadata metadata) throws SensitivePropertyProtectionException {
        // TODO: Implement
        return null;
    }

    public String generateRandom(Integer size) {
        GenerateRandomRequest request = new GenerateRandomRequest()
            .withNumberOfBytes(size);
        
        GenerateRandomResult response = client.generateRandom(request);
        return Hex.toHexString(response.getPlaintext().array());
    }

    public boolean providesScheme(String protectionScheme) throws SensitivePropertyProtectionException {
        return protectionScheme != null && protectionScheme.startsWith(IMPLEMENTATION_KEY);        
    }

    // TODO: Remove as this is unused and duplicates providesScheme? If required by SSPPF, invoke it from the #providesScheme method
    public static boolean canHandleScheme(String protectionScheme) throws SensitivePropertyProtectionException {
        return protectionScheme != null && protectionScheme.startsWith(IMPLEMENTATION_KEY);        
    }
    
}
