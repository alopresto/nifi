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

import org.apache.commons.lang3.StringUtils
import org.apache.nifi.security.util.CertificateUtils
import org.apache.nifi.toolkit.tls.v2.ca.NiFiCAService
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralNamesBuilder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate

class TlsToolkitUtil {
    private static final Logger logger = LoggerFactory.getLogger(TlsToolkitUtil.class)
    static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
    static final String END_CERT = "-----END CERTIFICATE-----"
    static final String DEFAULT_ALGORITHM = "RSA"
    static final String DEFAULT_SIGNING_ALGORITHM = "SHA256withRSA"
    static final String DEFAULT_ALIAS = "nifi-key"
    static final String DEFAULT_DN = "CN=nifi-ca, OU=NiFi"
    static final int DEFAULT_CERT_VALIDITY_DAYS = 1095
    static final int DEFAULT_KEY_SIZE = 2048
    static final int DEFAULT_PASSWORD_LENGTH = 30
    static final int PASSWORD_MIN_LENGTH = 16

    /**
     * Returns true if 256-bit key lengths are available.
     *
     * @return false if 128-bit keys are the strongest available
     */
    static boolean isUnlimitedStrengthCryptoAvailable() {
        Cipher.getMaxAllowedKeyLength("AES") > 128
    }

    /**
     * Returns a {@link KeyPair} containing the public and private key values for the provided algorithm and key size.
     *
     * @param algorithm "RSA" (default), "EC", "DSA", or "DiffieHellman"
     * @param keySize 2048 (default) or higher is recommended
     * @return the key pair
     */
    static KeyPair generateKeyPair(String algorithm = DEFAULT_ALGORITHM, int keySize = DEFAULT_KEY_SIZE) {
        logger.debug("Generating key pair for ${algorithm} with key size ${keySize}")
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm)
        generator.initialize(keySize)
        KeyPair keyPair = generator.generateKeyPair()
        logger.debug("Generated key pair ${keyPair}")
        keyPair
    }

    /**
     * Returns the HMAC (SHA-256) calculated over the public key using the provided token.
     *
     * @param token cannot be null and must be at least 16 bytes
     * @param publicKey the public key to use as (data) input
     * @return the HMAC/SHA-256(token, publicKey) in hex-encoded form
     * @throws GeneralSecurityException
     */
    static String calculateHMac(String token, PublicKey publicKey) throws GeneralSecurityException {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null")
        }
        byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8)
        if (tokenBytes.length < 16) {
            throw new GeneralSecurityException("Token does not meet minimum size of 16 bytes.")
        }
        SecretKeySpec keySpec = new SecretKeySpec(tokenBytes, "RAW")
        Mac mac = Mac.getInstance("Hmac-SHA256", BouncyCastleProvider.PROVIDER_NAME)
        mac.init(keySpec)
        return Hex.toHexString(mac.doFinal(getKeyIdentifier(publicKey)))
    }

    /**
     * Returns the {@code key identifier} of the public key. Used when calculating the HMAC.
     *
     * @param publicKey the public key to verify
     * @return the key identifier attribute of the public key
     * @throws NoSuchAlgorithmException
     */
    static byte[] getKeyIdentifier(PublicKey publicKey) throws NoSuchAlgorithmException {
        return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey).getKeyIdentifier()
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

    /**
     * Returns a String listing the {@code SubjectAlternativeNames} (if any) and their address
     * types contained in the provided {@link java.security.cert.X509Certificate}. Currently handles
     * String-formatted address types (see {@link #determineAddressType(int)}.
     *
     * @param certificate the X.509 certificate
     * @return a String listing the SANs or an empty String
     * @throws java.security.cert.CertificateParsingException if there is a problem parsing the certificate
     */
    static String formatSANForDisplay(X509Certificate certificate) throws CertificateParsingException {
        // The getter returns a Collection of Lists, each List is a GeneralName
        final Collection<List<?>> subjectAlternativeNames = certificate.getSubjectAlternativeNames()

        // The result can be null if no SAN are present
        if (subjectAlternativeNames == null) {
            return ""
        }

        List<String> stringAddresses = new ArrayList<>()
        for (List<?> altName : subjectAlternativeNames) {
            // The List is [0] == Integer representing type; [1] == String name or byte[] address in ASN.1 DER format
            int addressType = new Integer(altName.get(0).toString())
            // RFC 822 (1), DNS (2), URI (6), and IP addresses (7) are in String format
            if (addressType == 1 || addressType == 2 || addressType == 6 || addressType == 7) {
                stringAddresses.add("[" + determineAddressType(addressType) + "] " + altName.get(1).toString())
            } else {
                // TODO: Decode the ASN.1 DER byte[]
            }
        }
        return StringUtils.join(stringAddresses, ",")
    }

    /**
     * Returns a String indicating the address type as found in {@code SubjectAlternativeNames} in an X.509 certificate.
     *
     * Currently, the supported types are:
     *
     * 1 - RFC 822
     * 2 - DNS
     * 6 - URI
     * 7 - IP Address
     *
     * @param addressType the integer representation of the address type
     * @return a String name
     */
    static String determineAddressType(int addressType) {
        switch (addressType) {
            case 1: return "RFC 822"
            case 2: return "DNS"
            case 6: return "URI"
            case 7: return "IP Address"
            default: return "Unsupported Address Type"
        }
    }

    /**
     * Returns a {@code Certificate Signing Request} for the specified DN and SANs with the provided key pair.
     *
     * @param requestedDn
     * @param subjectAlternativeNames
     * @param keyPair
     * @param signingAlgorithm
     * @return
     * @throws OperatorCreationException
     */
    static JcaPKCS10CertificationRequest generateCertificateSigningRequest(String requestedDn, List<String> subjectAlternativeNames, KeyPair keyPair, String signingAlgorithm) throws OperatorCreationException {
        logger.debug("Generating CSR for DN ${requestedDn} with SANs ${subjectAlternativeNames}")
        JcaPKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(new X500Name(requestedDn), keyPair.getPublic())

        // Add Subject Alternative Name(s) (including the CN)
        try {
            crb.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, generateSubjectAlternativeNamesExtensions(subjectAlternativeNames + CertificateUtils.getCNFromDN(requestedDn)))
        } catch (IOException e) {
            throw new OperatorCreationException("Error while adding " + subjectAlternativeNames + " as Subject Alternative Name", e)
        }

        // Build the signer and the request
        JcaContentSignerBuilder csb = new JcaContentSignerBuilder(signingAlgorithm)
        def contentSigner = csb.build(keyPair.getPrivate())
        def certificationRequest = crb.build(contentSigner)
        new JcaPKCS10CertificationRequest(certificationRequest)
    }

    /**
     * Returns true if the {@code certificate} is signed by one of the {@code signingCertificates}. The list should
     * include the certificate itself to allow for self-signed certificates. If it does not, a self-signed certificate
     * will return {@code false}.
     *
     * @param certificate the certificate containing the signature being verified
     * @param signingCertificates a list of certificates which may have signed the certificate
     * @return true if one of the signing certificates did sign the certificate
     */
    static boolean verifyCertificateSignature(X509Certificate certificate, List<X509Certificate> signingCertificates) {
        String certificateDisplayInfo = getCertificateDisplayInfo(certificate)
        if (isVerbose()) {
            logger.info("Verifying the certificate signature for " + certificateDisplayInfo)
        }
        boolean signatureMatches = false
        for (X509Certificate signingCert : signingCertificates) {
            final String signingCertDisplayInfo = getCertificateDisplayInfo(signingCert)
            try {
                if (isVerbose()) {
                    logger.info("Attempting to verify certificate " + certificateDisplayInfo + " signature with " + signingCertDisplayInfo)
                }
                PublicKey pub = signingCert.getPublicKey()
                certificate.verify(pub)
                if (isVerbose()) {
                    logger.info("Certificate was signed by " + signingCertDisplayInfo)
                }
                signatureMatches = true
                break
            } catch (Exception e) {
                // Expected if the signature does not match
                if (isVerbose()) {
                    logger.warn("Certificate " + certificateDisplayInfo + " not signed by " + signingCertDisplayInfo + " [" + e.getLocalizedMessage() + "]")
                }
            }
        }
        return signatureMatches
    }

    private static String getCertificateDisplayInfo(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName()
    }

    static String pemEncode(Object certOrCsr) {
        def writer = new StringWriter()
        PemWriter pemWriter = new PemWriter(writer)
        pemWriter.writeObject(new JcaMiscPEMGenerator(certOrCsr))
        pemWriter.close()
        writer.toString()
    }

    static <T> T parsePem(Class<T> clazz, String pemContent) throws IOException {
        PEMParser pemParser = new PEMParser(new PemReader(new StringReader(pemContent)))
        Object object = pemParser.readObject()
        if (!clazz.isInstance(object)) {
            throw new IOException("Expected " + clazz + " but got " + object.getClass())
        }
        return (T) object
    }

    static JcaPKCS10CertificationRequest decodeCsr(String pemEncodedCsr) throws IOException {
        PEMParser pemParser = new PEMParser(new StringReader(pemEncodedCsr))
        Object o = pemParser.readObject()
        if (!PKCS10CertificationRequest.class.isInstance(o)) {
            throw new IOException("Expecting instance of " + PKCS10CertificationRequest.class + " but got " + o)
        }
        new JcaPKCS10CertificationRequest((PKCS10CertificationRequest) o)
    }

    static X509Certificate decodeCertificate(String pemEncodedCert) throws IOException {
        new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(parsePem(X509CertificateHolder.class, pemEncodedCert))
    }

    static PrivateKey decodePrivateKey(String pemEncodedKey) throws IOException {
        new JcaPEMKeyConverter().getKeyPair(parsePem(PEMKeyPair.class, pemEncodedKey)).private
    }

    static List<X509Certificate> splitPEMEncodedCertificateChain(String pemEncodedChain) {
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
        def pemList = pemEncodedChain.split("(?<=-----)(\n)(?=-----)") as List<String>
        pemList.collect { String pemEncodedCert ->
            // The decoding returns a BC X509CertificateHolder instance
            def certHolder = parsePem(X509CertificateHolder.class, pemEncodedCert)
            // Use the converter to get the actual certificate
            certConverter.getCertificate(certHolder)
        }
    }

    static boolean validateKeysMatch(PublicKey publicKey, PrivateKey privateKey) {
        if (publicKey instanceof RSAPublicKey) {
            def rsaPublicKey = publicKey as RSAPublicKey
            def rsaPrivateKey = privateKey as RSAPrivateKey

        }

    }

    static String wrapCertificateHeaders(String pemEncodedCert) {
        [BEGIN_CERT, pemEncodedCert, END_CERT].join("\n")
    }

    private static boolean isVerbose() {
        // TODO: When verbose mode is enabled via command-line flag, this will read the variable
        return true
    }

    static KeyStore generateOrLocateKeystore(String keystorePath, String keystorePassword, String alias, String dn) {
        KeyStore keystore

        try {
            // Try loading from file
            if (keystorePath) {
                keystore = loadKeystoreContainingAlias(keystorePath, keystorePassword, alias)
            } else {
                // TODO: Pass provided SANs for creating CA
                // TODO: Enforce password length & strength
                keystore = generateCAKeystore(dn, alias, keystorePassword)
            }
        } catch (KeyStoreException kse) {
            // Keystore loads but does not contain alias
            logger.warn("Because the expected alias could not be loaded, generate a new CA key and cert and inject it in this keystore")
            keystore = addCAToKeystore(dn, alias, keystorePassword, keystore)
            // Write the modified keystore to the file
            writeKeystore(keystore, keystorePassword, keystorePath)
        } catch (IOException ioe) {
            // No keystore at all
            logger.warn("Failed to load the keystore, generate a new keystore containing a CA key and cert")
            keystore = generateCAKeystore(dn, alias, keystorePassword)
            writeKeystore(keystore, keystorePassword, keystorePath)
        }

        keystore
    }

    static boolean writeKeystore(KeyStore keystore, String keystorePassword, String keystorePath) {
        try {
            FileOutputStream fos = new FileOutputStream(keystorePath)
            keystore.store(fos, keystorePassword.chars)
            true
        } catch (IOException e) {
            logger.error("Error writing keystore to ${keystorePath}", e)
            false
        }
    }

    static KeyStore addCAToKeystore(String dn, String alias, String keystorePassword, KeyStore keystore, String sans = "") {
        KeyPair caKeyPair = generateKeyPair()
        X509Certificate caCertificate = NiFiCAService.generateCACertificate(caKeyPair, dn, DEFAULT_SIGNING_ALGORITHM, DEFAULT_CERT_VALIDITY_DAYS, sans.tokenize(","))
        keystore.setKeyEntry(alias, caKeyPair.private, keystorePassword.chars, [caCertificate] as Certificate[])
        keystore
    }

    static KeyStore generateCAKeystore(String dn, String alias, String keystorePassword, String sans = "") {
        // TODO: Check keystorePassword for length & strength
        KeyStore keystore = KeyStore.getInstance("JKS")
        keystore.load(null, keystorePassword.chars)
        addCAToKeystore(dn, alias, keystorePassword, keystore, sans)
    }

    static KeyStore generateKeystoreFromExternalMaterial(X509Certificate publicCertificate, PrivateKey privateKey, String password, String alias = DEFAULT_ALIAS) {
        KeyStore keystore = KeyStore.getInstance("JKS")

        // Set the keystore password
        keystore.load(null, password.chars)

        // Set the key and cert as an entry
        keystore.setKeyEntry(alias, privateKey, password.chars, [publicCertificate] as Certificate[])
        logger.debug("Created keystore with alias ${alias} and certificate ${publicCertificate.subjectX500Principal}")

        keystore
    }


    static KeyStore loadKeystoreContainingAlias(String keystorePath, String keystorePassword, String alias) {
        KeyStore keystore = KeyStore.getInstance("JKS")
        File keystoreFile = new File(keystorePath)
        if (keystoreFile.exists()) {
            keystore.load(keystoreFile.newInputStream(), keystorePassword.chars)
            if (keystore.containsAlias(alias)) {
                return keystore
            } else {
                def msg = "Keystore at ${keystorePath} did not contain alias ${alias}"
                logger.warn(msg)
                throw new KeyStoreException(msg)
            }
        } else {
            def msg = "Keystore at ${keystorePath} cannot be loaded"
            logger.warn(msg)
            throw new IOException(msg)
        }
    }

    static String generateRandomPassword(int length = DEFAULT_PASSWORD_LENGTH) {
        if (length < PASSWORD_MIN_LENGTH) {
            def msg = "The requested password length (${length} chars) cannot be less than the minimum password length (${PASSWORD_MIN_LENGTH} chars)"
            logger.warn(msg)
            throw new InvalidKeyException(msg)
        }
        byte[] passwordBytes = new byte[length * 3 / 4]
        new SecureRandom().nextBytes(passwordBytes)
        String password = Base64.encoder.withoutPadding().encodeToString(passwordBytes)
        logger.debug("Generated random password of length ${password.length()}")
        password
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
