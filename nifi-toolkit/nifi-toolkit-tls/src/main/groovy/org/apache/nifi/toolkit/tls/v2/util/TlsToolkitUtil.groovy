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

package org.apache.nifi.toolkit.tls.v2.util


import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralNamesBuilder
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.Cipher

class TlsToolkitUtil {
    private static final Logger logger = LoggerFactory.getLogger(TlsToolkitUtil.class)

    /**
     * Returns true if 256-bit key lengths are available.
     *
     * @return false if 128-bit keys are the strongest available
     */
    static boolean isUnlimitedStrengthCryptoAvailable() {
        Cipher.getMaxAllowedKeyLength("AES") > 128
    }

    /**
     * Returns an {@link Extensions} object containing the {@code SubjectAlternativeName} entries.
     *
     * @param subjectAlternativeNames a list of {@code String}s identifying SANs
     * @return the extensions object
     * @throws IOException if a bad SAN is provided
     */
    static Extensions generateSubjectAlternativeNamesExtensions(List<String> subjectAlternativeNames) throws IOException {
        def gnb = new GeneralNamesBuilder()
        subjectAlternativeNames.each { String san ->
            gnb.addName(new GeneralName(GeneralName.dNSName, san))
        }

        GeneralNames subjectAltGeneralNames = gnb.build()
        ExtensionsGenerator extGen = new ExtensionsGenerator()
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltGeneralNames)
        return extGen.generate()
    }
//
//    /**
//     * Returns the parsed {@link java.security.KeyPair} from the provided {@link Reader}. The incoming format can be PKCS #8 or PKCS #1.
//     *
//     * @param pemKeyPairReader a reader with access to the serialized key pair
//     * @return the key pair
//     * @throws IOException if there is an error reading the key pair
//     */
//    static KeyPair parseKeyPairFromReader(Reader pemKeyPairReader) throws IOException {
//        // Instantiate PEMParser from Reader
//        try (PEMParser pemParser = new PEMParser(pemKeyPairReader)) {
//            // Read the object (deserialize)
//            Object parsedObject = pemParser.readObject()
//
//            // If this is an ASN.1 private key, it's in PKCS #8 format and wraps the actual RSA private key
//            if (PrivateKeyInfo.class.isInstance(parsedObject)) {
//                if (isVerbose()) {
//                    logger.info("Provided private key is in PKCS #8 format")
//                }
//                PEMKeyPair keyPair = convertPrivateKeyFromPKCS8ToPKCS1((PrivateKeyInfo) parsedObject)
//                return getKeyPair(keyPair)
//            } else if (PEMKeyPair.class.isInstance(parsedObject)) {
//                // Already in PKCS #1 format
//                return getKeyPair((PEMKeyPair) parsedObject)
//            } else {
//                logger.warn("Expected one of %s or %s but got %s", PrivateKeyInfo.class, PEMKeyPair.class, parsedObject.getClass())
//                throw new IOException("Expected private key in PKCS #1 or PKCS #8 unencrypted format")
//            }
//        }
//    }
//
//    /**
//     * Returns a {@link KeyPair} instance containing the {@link java.security.cert.X509Certificate} public key and the {@link java.security.spec.PKCS8EncodedKeySpec} private key from the PEM-encoded {@link PEMKeyPair}.
//     *
//     * @param keyPair the key pair in PEM format
//     * @return the key pair in a format which provides for direct access to the keys
//     * @throws org.bouncycastle.openssl.PEMException if there is an error converting the key pair
//     */
//    private static KeyPair getKeyPair(PEMKeyPair keyPair) throws PEMException {
//        return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getKeyPair(keyPair)
//    }
//
//    /**
//     * Returns a {@link PEMKeyPair} object with direct access to the public and private keys given a PKCS #8 private key.
//     *
//     * @param privateKeyInfo the PKCS #8 private key info
//     * @return the PKCS #1 public and private key pair
//     * @throws IOException if there is an error converting the key pair
//     */
//    private static PEMKeyPair convertPrivateKeyFromPKCS8ToPKCS1(PrivateKeyInfo privateKeyInfo) throws IOException {
//        // Parse the key wrapping to determine the internal key structure
//        ASN1Encodable asn1PrivateKey = privateKeyInfo.parsePrivateKey()
//
//        // Convert the parsed key to an RSA private key
//        RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(asn1PrivateKey)
//
//        // Create the RSA public key from the modulus and exponent
//        RSAPublicKey pubSpec = new RSAPublicKey(
//                keyStruct.getModulus(), keyStruct.getPublicExponent())
//
//        // Create an algorithm identifier for forming the key pair
//        AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
//        if (isVerbose()) {
//            logger.info("Converted private key from PKCS #8 to PKCS #1 RSA private key")
//        }
//
//        // Create the key pair container
//        return new PEMKeyPair(new SubjectPublicKeyInfo(algId, pubSpec), new PrivateKeyInfo(algId, keyStruct))
//    }

}
