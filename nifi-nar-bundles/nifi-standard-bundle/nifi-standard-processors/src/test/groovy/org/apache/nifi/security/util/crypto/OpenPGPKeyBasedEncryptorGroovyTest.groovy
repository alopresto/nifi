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
package org.apache.nifi.security.util.crypto


import org.apache.commons.codec.binary.Hex
import org.apache.nifi.processor.io.StreamCallback
import org.apache.nifi.security.util.EncryptionMethod
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.spec.DHParameterSpec
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security

@RunWith(JUnit4.class)
class OpenPGPKeyBasedEncryptorGroovyTest {
    private static final Logger logger = LoggerFactory.getLogger(OpenPGPKeyBasedEncryptorGroovyTest.class)

    private static final String PGP_ASCII_ALGO = "PGP-ASCII-ARMOR"
    private static final String PGP_ALGO = "PGP"
    private static final int DEFAULT_CIPHER = 7 // AES-128
    private static final String PROVIDER = "BC"

    private final File plainFile = new File("src/test/resources/TestEncryptContent/text.txt")
    private final File unsignedFile = new File("src/test/resources/TestEncryptContent/text.txt.unsigned.gpg")
    private final File encryptedFile = new File("src/test/resources/TestEncryptContent/text.txt.gpg")

    private static final String RSA_SECRET_KEYRING_PATH = "src/test/resources/TestEncryptContent/secring.gpg"
    private static final String RSA_PUBLIC_KEYRING_PATH = "src/test/resources/TestEncryptContent/pubring.gpg"
    private static final String RSA_USER_ID = "NiFi PGP Test Key (Short test key for NiFi PGP unit tests) <alopresto.apache+test@gmail.com>"

    private static final String DSA_SECRET_KEYRING_PATH = "src/test/resources/TestEncryptContent/dsa-pubring.gpg"
    private static final String DSA_PUBLIC_KEYRING_PATH = "src/test/resources/TestEncryptContent/dsa-pubring.gpg"
    private static final String DSA_PUBLIC_KEY_ARMORED_PATH = "src/test/resources/TestEncryptContent/dsa-public.asc"
    private static final String DSA_USER_ID = "NiFi Test DSA/EG Key Pair (Unit test resource for OpenPGPKeyBasedEncryptor) <test@nifi.apache.org>"
    private static final String DSA_FINGERPRINT_SHORT = "9a 51 95 f4 f2 a4 a8 83"

    private static final String DSA_SMALL_PUBLIC_KEYRING_PATH = "src/test/resources/TestEncryptContent/dsa-small-pubring.gpg"
    private static final String DSA_SMALL_USER_ID = "NiFi Test DSA/EG Key Pair (Unit test resource for OpenPGPKeyBasedEncryptor - 1024 bytes) <test@nifi.apache.org>"

    private static final String PASSWORD = "thisIsABadPassword"

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder()

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @AfterClass
    static void tearDownOnce() throws Exception {
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
    }

    @Test
    void testShouldRetrieveRSAKeyByUserId() throws Exception {
        // Arrange
        String userId = RSA_USER_ID

        // Act
        PGPPublicKey publicKey = OpenPGPKeyBasedEncryptor.getPublicKey(userId, RSA_PUBLIC_KEYRING_PATH)
        logger.info("Read public key ${publicKey.dump()} for user ID: ${userId}")

        // Assert
        assert publicKey.algorithm == PGPPublicKey.RSA_GENERAL
    }

    @Test
    void testShouldRetrieveDSAKeyByUserId() throws Exception {
        // Arrange
        String userId = DSA_USER_ID

        // Act
        PGPPublicKey publicKey = OpenPGPKeyBasedEncryptor.getDSAPublicKey(userId, DSA_PUBLIC_KEYRING_PATH)
        logger.info("Read public key ${publicKey.dump()} for user ID: ${userId}")

        // Assert
        assert publicKey.algorithm == PGPPublicKey.DSA
    }

    @Test
    void testShouldRetrieveElGamalSubKeyByUserId() throws Exception {

    }

    @Test
    void testShouldPerformEncryptionWithExportedArmoredPublicDSAKeyByUserId() throws Exception {
        // Arrange
        String userId = DSA_USER_ID
        String keyPath = DSA_PUBLIC_KEY_ARMORED_PATH

        // Act
        PGPPublicKey publicKey = OpenPGPKeyBasedEncryptor.getDSAPublicKey(userId, keyPath)
        logger.info("Read public key ${publicKey.dump()} for user ID: ${userId}")

        // Assert
        assert publicKey.algorithm == PGPPublicKey.DSA
    }

    @Test
    void testShouldPerformEncryptionWithExportedArmoredPublicDSAKeyByFingerprint() throws Exception {
        // Arrange
        String fingerprint = DSA_FINGERPRINT_SHORT
        String keyPath = DSA_PUBLIC_KEY_ARMORED_PATH

        // Act
        PGPPublicKey publicKey = OpenPGPKeyBasedEncryptor.getDSAPublicKey(fingerprint, keyPath)
        logger.info("Read public key ${publicKey.dump()} for fingerprint: ${fingerprint}")

        // Assert
        assert publicKey.algorithm == PGPPublicKey.DSA
    }

    @Test
    void testShouldPerformEncryptionWithExportedBinaryPublicDSAKey() throws Exception {

    }

    // TODO: Test various fingerprint formats (positive flow, negative flow, short ID, long ID, full, caps, spacing, leading indicator, etc.)
    // TODO: Test various user ID formats (full uid, name, email, caps, etc.)

    @Test
    void testShouldReadDSAKeyRing() throws Exception {
        // Arrange
        String userId = ""
        String filename = "unit-test-file"
        File dsaPKRCFile = new File(DSA_PUBLIC_KEYRING_PATH)
        File dsaSmallPKRCFile = new File(DSA_SMALL_PUBLIC_KEYRING_PATH)
        File rsaPKRCFile = new File(RSA_PUBLIC_KEYRING_PATH)

        // TODO: Test by actually reading the keyring

        // Generate a DSA/EG keypair and pass it directly as an input stream
        try {
            InputStream publicKeysStream = generateTemporaryDSAEGKeyPair()
            PGPPublicKeyRingCollection generatedCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeysStream), new BcKeyFingerprintCalculator())
            logger.generated("Read public keyring collection: ${generatedCollection.dump()}")
            assert generatedCollection.size() == 1
            PGPPublicKey key = generatedCollection.first().getPublicKey()
            logger.generated("Read public key: ${key.dump()}")
            Long keyId = key.keyID
            byte[] fingerprint = key.fingerprint
            assert generatedCollection.contains(keyId)
            assert generatedCollection.contains(fingerprint)
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the decoded stream: ${e.localizedMessage}")
        }

        // Read the input stream directly (works with RSA)
        try {
            PGPPublicKeyRingCollection rsaCollection = new PGPPublicKeyRingCollection(rsaPKRCFile.newInputStream(), new BcKeyFingerprintCalculator())
            logger.rsa("Read public keyring collection: ${rsaCollection.dump()}")
            assert rsaCollection.size() > 0
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the undecoded stream: ${e.localizedMessage}")
        }

        // Read the (small key) input stream directly (works with RSA)
        try {
            PGPPublicKeyRingCollection ioeCollection = new PGPPublicKeyRingCollection(dsaSmallPKRCFile.newInputStream(), new BcKeyFingerprintCalculator())
            logger.stream("Read public keyring collection: ${ioeCollection.dump()}")
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the undecoded stream: ${e.localizedMessage}")
        }

        // Read the input stream directly (works with RSA)
        try {
            PGPPublicKeyRingCollection ioeCollection = new PGPPublicKeyRingCollection(dsaPKRCFile.newInputStream(), new BcKeyFingerprintCalculator())
            logger.stream("Read public keyring collection: ${ioeCollection.dump()}")
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the undecoded stream: ${e.localizedMessage}")
        }

        // Read the input stream via decoder (works with RSA)
        try {
            PGPPublicKeyRingCollection decodedCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(dsaPKRCFile.newInputStream()), new BcKeyFingerprintCalculator())
            logger.decoded("Read public keyring collection: ${decodedCollection.dump()}")
            assert decodedCollection.size() == 0
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the decoded stream: ${e.localizedMessage}")
        }

        // Read the file bytes directly
        try {
            PGPPublicKeyRingCollection byteCollection = new PGPPublicKeyRingCollection(dsaPKRCFile.bytes, new BcKeyFingerprintCalculator())
            logger.bytes("Read public keyring collection: ${byteCollection.dump()}")
            assert byteCollection.size() == 0
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the bytes: ${e.localizedMessage}")
        }

        // Read the input stream via decoder and JCA fingerprinter (works with RSA)
        try {
            PGPPublicKeyRingCollection decodedCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(dsaPKRCFile.newInputStream()), new JcaKeyFingerprintCalculator())
            logger.decoded("Read public keyring collection: ${decodedCollection.dump()}")
            assert decodedCollection.size() == 0
        } catch (IOException e) {
            logger.expected("Encountered an exception reading the decoded stream: ${e.localizedMessage}")
        }

        // Act
        OpenPGPKeyBasedEncryptor encryptor = new OpenPGPKeyBasedEncryptor(PGP_ASCII_ALGO, DEFAULT_CIPHER, PROVIDER, DSA_PUBLIC_KEYRING_PATH, userId, null, filename)
        logger.info("Instantiated encryptor for DSA keyring")

        // Assert
        encryptor.keyring == DSA_PUBLIC_KEYRING_PATH
    }

    /**
     * Returns an {@link InputStream} containing the public keys as they would be persisted in a *.gpg keyring. The (modified) construction code is copied from Bouncy Castle
     *
     * @seealso DSAElGamalKeyRingGenerator.java*
     * @return the public keys
     */
    InputStream generateTemporaryDSAEGKeyPair() {
        ByteArrayOutputStream secretOut = new ByteArrayOutputStream()
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream()

        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC")
        dsaKpg.initialize(1024)
        KeyPair dsaKp = dsaKpg.generateKeyPair()
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC")
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16)
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16)
        DHParameterSpec elParams = new DHParameterSpec(p, g)
        elgKpg.initialize(elParams)
        KeyPair elgKp = elgKpg.generateKeyPair()
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date())
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date())
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1)
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                "NiFi Temporary DSA/EG Key", sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(PASSWORD.chars))
        keyRingGen.addSubKey(elgKeyPair)
        keyRingGen.generateSecretKeyRing().encode(secretOut)
        secretOut.close()
        keyRingGen.generatePublicKeyRing().encode(publicOut)
        publicOut.close()

        return new ByteArrayInputStream(publicOut.toByteArray())
    }

// TODO: Test method to read from single public key file

    @Test
    void testShouldEncryptAndDecrypt() throws Exception {
        for (int i = 1; i < 14; i++) {
            if (PGPEncryptedData.SAFER != i) { // SAFER cipher is not supported and therefore its test is skipped
                Integer cipher = i
                logger.info("Testing PGP encryption with " + PGPUtil.getSymmetricCipherName(cipher) + " cipher.")
                // Arrange
                final String PLAINTEXT = "This is a plaintext message."
                logger.info("Plaintext: {}", PLAINTEXT)
                InputStream plainStream = new ByteArrayInputStream(PLAINTEXT.getBytes("UTF-8"))
                OutputStream cipherStream = new ByteArrayOutputStream()
                OutputStream recoveredStream = new ByteArrayOutputStream()

                // No file, just streams
                String filename = "tempFile.txt"


                // Encryptor does not require password
                OpenPGPKeyBasedEncryptor encryptor = new OpenPGPKeyBasedEncryptor(
                        EncryptionMethod.PGP.getAlgorithm(), cipher, EncryptionMethod.PGP.getProvider(), PUBLIC_KEYRING_PATH, USER_ID, new char[0], filename)
                StreamCallback encryptionCallback = encryptor.getEncryptionCallback()

                OpenPGPKeyBasedEncryptor decryptor = new OpenPGPKeyBasedEncryptor(
                        EncryptionMethod.PGP.getAlgorithm(), cipher, EncryptionMethod.PGP.getProvider(), SECRET_KEYRING_PATH, USER_ID, PASSWORD.toCharArray(), filename)
                StreamCallback decryptionCallback = decryptor.getDecryptionCallback()

                // Act
                encryptionCallback.process(plainStream, cipherStream)

                final byte[] cipherBytes = ((ByteArrayOutputStream) cipherStream).toByteArray()
                logger.info("Encrypted: {}", Hex.encodeHexString(cipherBytes))
                InputStream cipherInputStream = new ByteArrayInputStream(cipherBytes)

                decryptionCallback.process(cipherInputStream, recoveredStream)

                // Assert
                byte[] recoveredBytes = ((ByteArrayOutputStream) recoveredStream).toByteArray()
                String recovered = new String(recoveredBytes, "UTF-8")
                logger.info("Recovered: {}", recovered)
                assert PLAINTEXT.equals(recovered)
            }
        }
    }

    @Test
    void testShouldDecryptExternalFile() throws Exception {
        for (int i = 1; i < 14; i++) {
            if (PGPEncryptedData.SAFER != i) { // SAFER cipher is not supported and therefore its test is skipped
                Integer cipher = i
                // Arrange
                byte[] plainBytes = Files.readAllBytes(Paths.get(plainFile.getPath()))
                final String PLAINTEXT = new String(plainBytes, "UTF-8")

                InputStream cipherStream = new FileInputStream(unsignedFile)
                OutputStream recoveredStream = new ByteArrayOutputStream()

                // No file, just streams
                String filename = unsignedFile.getName()

                OpenPGPKeyBasedEncryptor encryptor = new OpenPGPKeyBasedEncryptor(
                        EncryptionMethod.PGP.getAlgorithm(), cipher, EncryptionMethod.PGP.getProvider(), SECRET_KEYRING_PATH, USER_ID, PASSWORD.toCharArray(), filename)

                StreamCallback decryptionCallback = encryptor.getDecryptionCallback()

                // Act
                decryptionCallback.process(cipherStream, recoveredStream)

                // Assert
                byte[] recoveredBytes = ((ByteArrayOutputStream) recoveredStream).toByteArray()
                String recovered = new String(recoveredBytes, "UTF-8")
                logger.info("Recovered: {}", recovered)
                Assert.assertEquals("Recovered text", PLAINTEXT, recovered)
            }
        }
    }
}
