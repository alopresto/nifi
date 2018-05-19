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
package org.apache.nifi.security.util.crypto.hkdf;

import at.favre.lib.crypto.HKDF;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class wraps the HKDF (Hash-based Key Derivation Function) algorithm described in <a href="https://tools.ietf.org/html/rfc5869">IETF RFC 5869</a> and implemented by Patrick Favre-Bulle in the <a href="https://github.com/patrickfav/hkdf">hkdf</a> module to make it simpler to consume for NiFi uses. The full library is still available for direct interaction in the event of other requirements.
 * <p>
 * The default methods use HMAC/SHA-256 and a salt of the same length as the input key material (IKM). They return output key material (OKM) of the same length as the IKM.
 *
 * Details of default implementation:
 *
 * <pre>
 * {@code
 * salt = static salt of length IKM.length
 * L = IKM.length
 * info = salt
 *
 * byte[] pseudoRandomKey = hkdf.extract(salt, IKM);
 * byte[] derivedKey = hkdf.expand(pseudoRandomKey, info, L);
 * }
 * </pre>
 */
public class Hkdf {
    private static final Logger logger = LoggerFactory.getLogger(Hkdf.class);

    public static byte[] STATIC_SALT_16 = "static NiFi salt".getBytes(StandardCharsets.UTF_8);
    public static byte[] STATIC_SALT_32 = "static NiFi salt length 32 bytes".getBytes(StandardCharsets.UTF_8);
    public static byte[] STATIC_SALT_64 = "this is a static NiFi salt and has a constant length of 64 bytes".getBytes(StandardCharsets.UTF_8);

    /**
     * Returns the static salt of the requested length. If no salt is available for the requested length, a 16 byte salt is returned.
     *
     * @param length the desired salt length in bytes
     * @return the salt
     */
    public static byte[] getStaticSalt(int length) {
        switch (length) {
            default:
                logger.warn("There is no static salt of length {} bytes; 16 byte salt returned", new Object[]{length});
            case 16:
                return STATIC_SALT_16;
            case 32:
                return STATIC_SALT_32;
            case 64:
                return STATIC_SALT_64;
        }
    }

    /**
     * Returns a derived key of the same length as the input key material.
     *
     * @param salt             the salt value in raw bytes
     * @param inputKeyMaterial the input key material in raw bytes
     * @return the derived key in raw bytes
     */
    public static byte[] deriveKey(byte[] salt, byte[] inputKeyMaterial) {
        HKDF hkdf = HKDF.fromHmacSha256();

        // Extract the "raw" data to create output with concentrated entropy
        byte[] pseudoRandomKey = hkdf.extract(salt, inputKeyMaterial);

        // Create expanded bytes
        byte[] derivedKey = hkdf.expand(pseudoRandomKey, salt, inputKeyMaterial.length);

        return derivedKey;
    }

    /**
     * Returns a derived key of the same length as the input key material. This method uses a static salt available at {@link Hkdf#getStaticSalt(int)} where the input is the length of
     * the input key material in bytes.
     *
     * @param inputKeyMaterial the input key material in raw bytes
     * @return the derived key in raw bytes
     */
    public static byte[] deriveKey(byte[] inputKeyMaterial) {
        return deriveKey(getStaticSalt(inputKeyMaterial.length), inputKeyMaterial);
    }

    /**
     * Returns a derived key of the same length as the input key material. This method uses a static salt available at {@link Hkdf#getStaticSalt(int)} where the input is the length of
     * the input key material in bytes. The output is in lowercase.
     *
     * @param saltHex             the salt in hex encoding
     * @param inputKeyMaterialHex the input key material in hex encoding
     * @return the derived key in hex encoding
     */
    public static String deriveKeyHex(String saltHex, String inputKeyMaterialHex) {
        try {
            return Hex.encodeHexString(deriveKey(Hex.decodeHex(saltHex), Hex.decodeHex(inputKeyMaterialHex)));
        } catch (DecoderException e) {
            logger.error("Encountered an error deriving a key using HKDF because of invalid hex for salt or IKM");
            throw new IllegalArgumentException("The salt and IKM must be valid hex");
        }
    }

    /**
     * Returns a derived key of the same length as the input key material. The output is in lowercase.
     *
     * @param inputKeyMaterialHex the input key material in hex encoding
     * @return the derived key in hex encoding
     */
    public static String deriveKeyHex(String inputKeyMaterialHex) {
        return deriveKeyHex(Hex.encodeHexString(getStaticSalt(inputKeyMaterialHex.length() / 2)), inputKeyMaterialHex);
    }

}
