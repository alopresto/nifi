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
package org.apache.nifi.util.config

import ch.qos.logback.core.AppenderBase
import org.apache.commons.codec.binary.Hex
import org.apache.log4j.spi.LoggingEvent
import org.apache.nifi.toolkit.tls.commandLine.CommandLineParseException
import org.apache.nifi.util.NiFiProperties
import org.apache.nifi.util.console.TextDevice
import org.apache.nifi.util.console.TextDevices
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.crypto.Cipher
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyException
import java.security.Security

@RunWith(JUnit4.class)
class ConfigEncryptionToolTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(ConfigEncryptionToolTest.class)

    private static final String KEY_HEX = "0123456789ABCDEFFEDCBA9876543210" * 2
    private static final String PASSWORD = "thisIsABadPassword"

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
        TestAppender.reset()
        NiFiProperties.@instance = null
    }

    @Test
    void testShouldPrintHelpMessage() {
        // Arrange
        def flags = ["-h", "--help"]
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        flags.each { String arg ->
            def msg = shouldFail(CommandLineParseException) {
                tool.parse([arg] as String[])
            }

            // Assert
            assert msg == null
//            assert TestAppender.events.last().toString() == "Some message"
        }
    }

    @Test
    void testShouldParseBootstrapConfArgument() {
        // Arrange
        def flags = ["-b", "--bootstrapConf"]
        String bootstrapPath = "src/test/resources/bootstrap.conf"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        flags.each { String arg ->
            tool.parse([arg, bootstrapPath] as String[])
            logger.info("Parsed bootstrap.conf location: ${tool.bootstrapConfPath}")

            // Assert
            assert tool.bootstrapConfPath == bootstrapPath
        }
    }

    @Test
    void testParseShouldPopulateDefaultBootstrapConfArgument() {
        // Arrange
        String bootstrapPath = "conf/bootstrap.conf"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        tool.parse([] as String[])
        logger.info("Parsed bootstrap.conf location: ${tool.bootstrapConfPath}")

        // Assert
        assert new File(tool.bootstrapConfPath).getPath() == new File(bootstrapPath).getPath()
    }

    @Test
    void testShouldParseNiFiPropertiesArgument() {
        // Arrange
        def flags = ["-n", "--niFiProperties"]
        String niFiPropertiesPath = "src/test/resources/nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        flags.each { String arg ->
            tool.parse([arg, niFiPropertiesPath] as String[])
            logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

            // Assert
            assert tool.niFiPropertiesPath == niFiPropertiesPath
        }
    }

    @Test
    void testParseShouldPopulateDefaultNiFiPropertiesArgument() {
        // Arrange
        String niFiPropertiesPath = "conf/nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        tool.parse([] as String[])
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        // Assert
        assert new File(tool.niFiPropertiesPath).getPath() == new File(niFiPropertiesPath).getPath()
    }

    @Test
    void testShouldParseOutputNiFiPropertiesArgument() {
        // Arrange
        def flags = ["-o", "--outputNiFiProperties"]
        String niFiPropertiesPath = "src/test/resources/nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        flags.each { String arg ->
            tool.parse([arg, niFiPropertiesPath] as String[])
            logger.info("Parsed output nifi.properties location: ${tool.outputNiFiPropertiesPath}")

            // Assert
            assert tool.outputNiFiPropertiesPath == niFiPropertiesPath
        }
    }

    @Test
    void testParseShouldPopulateDefaultOutputNiFiPropertiesArgument() {
        // Arrange
        String niFiPropertiesPath = "conf/nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        tool.parse([] as String[])
        logger.info("Parsed output nifi.properties location: ${tool.outputNiFiPropertiesPath}")

        // Assert
        assert new File(tool.outputNiFiPropertiesPath).getPath() == new File(niFiPropertiesPath).getPath()
    }

    @Ignore("Need to get TestAppender working again")
    @Test
    void testParseShouldWarnIfNiFiPropertiesWillBeOverwritten() {
        // Arrange
        String niFiPropertiesPath = "conf/nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        tool.parse("-n ${niFiPropertiesPath} -o ${niFiPropertiesPath}".split(" ") as String[])
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")
        logger.info("Parsed output nifi.properties location: ${tool.outputNiFiPropertiesPath}")

        // Assert
        assert TestAppender.events.last().toString() == "The source nifi.properties and destination nifi.properties are identical \\[.*\\] so the original will be overwritten"
    }

    @Test
    void testShouldParseKeyArgument() {
        // Arrange
        def flags = ["-k", "--key"]
        ConfigEncryptionTool tool = new ConfigEncryptionTool()

        // Act
        flags.each { String arg ->
            tool.parse([arg, KEY_HEX] as String[])
            logger.info("Parsed key: ${tool.keyHex}")

            // Assert
            assert tool.keyHex == KEY_HEX
        }
    }

    @Test
    void testShouldLoadNiFiProperties() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/nifi_with_sensitive_properties_unprotected.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath] as String[]

        String oldFilePath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        // Act
        NiFiProperties properties = tool.loadNiFiProperties()
        logger.info("Loaded NiFiProperties from ${tool.niFiPropertiesPath}")

        // Assert
        assert properties
        assert properties.size() > 0

        // The system variable was reset to the original value
        assert System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH) == oldFilePath
    }

    @Test
    void testShouldReadKeyFromConsole() {
        // Arrange
        List<String> keyValues = [
                "0123 4567",
                KEY_HEX,
                "   ${KEY_HEX}   ",
                "non-hex-chars",
        ]

        // Act
        keyValues.each { String key ->
            TextDevice mockConsoleDevice = TextDevices.streamDevice(new ByteArrayInputStream(key.bytes), new ByteArrayOutputStream())
            String readKey = ConfigEncryptionTool.readKeyFromConsole(mockConsoleDevice)
            logger.info("Read key: [${readKey}]")

            // Assert
            assert readKey == key
        }
    }

    @Test
    void testShouldParseKey() {
        // Arrange
        Map<String, String> keyValues = [
                (KEY_HEX)                         : KEY_HEX,
                "   ${KEY_HEX}   "                : KEY_HEX,
                "xxx${KEY_HEX}zzz"                : KEY_HEX,
                ((["0123", "4567"] * 4).join("-")): "01234567" * 4,
                ((["89ab", "cdef"] * 4).join(" ")): "89ABCDEF" * 4,
                (KEY_HEX.toLowerCase())           : KEY_HEX,
                (KEY_HEX[0..<32])                 : KEY_HEX[0..<32],
                (KEY_HEX[0..<48])                 : KEY_HEX[0..<48]
        ]

        // Act
        keyValues.each { String key, final String EXPECTED_KEY ->
            logger.info("Reading key: [${key}]")
            String parsedKey = ConfigEncryptionTool.parseKey(key)
            logger.info("Parsed key:  [${parsedKey}]")

            // Assert
            assert parsedKey == EXPECTED_KEY
        }
    }

    @Test
    void testParseKeyShouldThrowExceptionForInvalidKeys() {
        // Arrange
        List<String> keyValues = [
                "0123 4567",
                "non-hex-chars",
                KEY_HEX[0..<-1],
                "&ITD SF^FI&&%SDIF"
        ]

        def validKeyLengths = ConfigEncryptionTool.getValidKeyLengths()
        def bitLengths = validKeyLengths.collect { it / 4 }
        String secondHalf = /\[${validKeyLengths.join(", ")}\] bits / +
                /\(\[${bitLengths.join(", ")}\]/ + / hex characters\)/.toString()

        // Act
        keyValues.each { String key ->
            logger.info("Reading key: [${key}]")
            def msg = shouldFail(KeyException) {
                String parsedKey = ConfigEncryptionTool.parseKey(key)
                logger.info("Parsed key:  [${parsedKey}]")
            }
            logger.expected(msg)
            int trimmedKeySize = key.replaceAll("[^0-9a-fA-F]", "").size()

            // Assert
            assert msg =~ "The key \\(${trimmedKeySize} hex chars\\) must be of length ${secondHalf}"
        }
    }

    @Test
    void testShouldDeriveKeyFromPassword() {
        // Arrange

        // Mocked for deterministic output and performance in test -- SCrypt is not under test here
        SCrypt.metaClass.'static'.generate = { byte[] pw, byte[] s, int N, int r, int p, int dkLen ->
            logger.mock("Mock SCrypt.generate(${Hex.encodeHexString(pw)}, ${Hex.encodeHexString(s)}, ${N}, ${r}, ${p}, ${dkLen})")
            logger.mock("Returning ${KEY_HEX[0..<dkLen * 2]}")
            Hex.decodeHex(KEY_HEX[0..<dkLen * 2] as char[])
        }

        logger.info("Using password: [${PASSWORD}]")

        // Act
        String derivedKey = ConfigEncryptionTool.deriveKeyFromPassword(PASSWORD)
        logger.info("Derived key:  [${derivedKey}]")

        // Assert
        assert derivedKey == KEY_HEX

        SCrypt.metaClass.'static' = null
    }

    @Test
    void testShouldActuallyDeriveKeyFromPassword() {
        // Arrange
        logger.info("Using password: [${PASSWORD}]")

        // Act
        String derivedKey = ConfigEncryptionTool.deriveKeyFromPassword(PASSWORD)
        logger.info("Derived key:  [${derivedKey}]")

        // Assert
        assert derivedKey.length() == (Cipher.getMaxAllowedKeyLength("AES") > 128 ? 64 : 32)
    }

    @Test
    void testDeriveKeyFromPasswordShouldTrimPassword() {
        // Arrange
        final String PASSWORD_SPACES = "   ${PASSWORD}   "

        def attemptedPasswords = []

        // Mocked for deterministic output and performance in test -- SCrypt is not under test here
        SCrypt.metaClass.'static'.generate = { byte[] pw, byte[] s, int N, int r, int p, int dkLen ->
            logger.mock("Mock SCrypt.generate(${Hex.encodeHexString(pw)}, ${Hex.encodeHexString(s)}, ${N}, ${r}, ${p}, ${dkLen})")
            attemptedPasswords << new String(pw)
            logger.mock("Returning ${KEY_HEX[0..<dkLen * 2]}")
            Hex.decodeHex(KEY_HEX[0..<dkLen * 2] as char[])
        }

        // Act
        [PASSWORD, PASSWORD_SPACES].each { String password ->
            logger.info("Using password: [${password}]")
            String derivedKey = ConfigEncryptionTool.deriveKeyFromPassword(password)
            logger.info("Derived key:  [${derivedKey}]")
        }

        // Assert
        assert attemptedPasswords.size() == 2
        assert attemptedPasswords.every { it == PASSWORD }

        SCrypt.metaClass.'static' = null
    }

    @Test
    void testDeriveKeyFromPasswordShouldThrowExceptionForInvalidPasswords() {
        // Arrange
        List<String> passwords = [
                (null),
                "",
                "      ",
                "shortpass",
                "shortwith    "
        ]

        // Act
        passwords.each { String password ->
            logger.info("Reading password: [${password}]")
            def msg = shouldFail(KeyException) {
                String derivedKey = ConfigEncryptionTool.deriveKeyFromPassword(password)
                logger.info("Derived key:  [${derivedKey}]")
            }
            logger.expected(msg)

            // Assert
            assert msg == "Cannot derive key from empty/short password -- password must be at least 12 characters"
        }
    }

    @Test
    void testMainShouldThrowExceptionForInvalidPassword() {
        // Arrange
        String badPassword = ""
        def args = ["-p", badPassword]
        logger.info("Using args: ${args}")

        // Act
        def msg = shouldFail(CommandLineParseException) {
            ConfigEncryptionTool.main(args as String[])
        }
        logger.expected(msg)

        // Assert
        assert msg == "Cannot derive key from empty/short password -- password must be at least 12 characters"
    }

    @Test
    void testShouldHandleKeyAndPasswordFlag() {
        // Arrange
        def args = ["-k", KEY_HEX, "-p", PASSWORD]
        logger.info("Using args: ${args}")

        // Act
        def msg = shouldFail(CommandLineParseException) {
            new ConfigEncryptionTool().parse(args as String[])
        }
        logger.expected(msg)

        // Assert
        assert msg == "Only one of password and key can be used"
    }

    @Test
    void testShouldNotLoadMissingNiFiProperties() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/non_existent_nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath] as String[]

        String oldFilePath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        // Act
        def msg = shouldFail(CommandLineParseException) {
            NiFiProperties properties = tool.loadNiFiProperties()
            logger.info("Loaded NiFiProperties from ${tool.niFiPropertiesPath}")
        }

        // Assert
        assert msg == "Cannot load NiFiProperties from [${niFiPropertiesPath}]".toString()

        // The system variable was reset to the original value
        assert System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH) == oldFilePath
    }

    @Test
    void testLoadNiFiPropertiesShouldHandleReadFailure() {
        // Arrange
        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File workingFile = new File("tmp_nifi.properties")
        workingFile.delete()

        Files.copy(inputPropertiesFile.toPath(), workingFile.toPath())
        // Empty set of permissions
        Files.setPosixFilePermissions(workingFile.toPath(), [] as Set)
        logger.info("Set POSIX permissions to ${Files.getPosixFilePermissions(workingFile.toPath())}")

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)

        // Act
        def msg = shouldFail(IOException) {
            tool.loadNiFiProperties()
            logger.info("Read nifi.properties")
        }
        logger.expected(msg)

        // Assert
        assert msg == "Cannot load NiFiProperties from [${workingFile.path}]".toString()

        workingFile.deleteOnExit()
    }

    @Test
    void testShouldEncryptSensitiveProperties() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/nifi_with_sensitive_properties_unprotected.properties"
        String newPropertiesPath = "src/test/resources/tmp_encrypted_nifi.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath, "-o", newPropertiesPath] as String[]

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        tool.keyHex = KEY_HEX

        NiFiProperties rawProperties = tool.loadNiFiProperties()
        assert !rawProperties.hasProtectedKeys()

        // Act
        NiFiProperties encryptedProperties = tool.encryptSensitiveProperties(rawProperties)
        logger.info("Encrypted sensitive properties")

        // Assert
        assert encryptedProperties.hasProtectedKeys()

        // Ensure that all non-empty sensitive properties are marked as protected
        final Set<String> EXPECTED_PROTECTED_KEYS = encryptedProperties
                .getSensitivePropertyKeys().findAll { String k ->
            rawProperties.getProperty(k)
        } as Set<String>
        assert encryptedProperties.getProtectedPropertyKeys().keySet() == EXPECTED_PROTECTED_KEYS
    }

    @Test
    void testShouldUpdateBootstrapContentsWithKey() {
        // Arrange
        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        tool.keyHex = KEY_HEX

        List<String> originalLines = [
                ConfigEncryptionTool.BOOTSTRAP_KEY_COMMENT,
                "${ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX}="
        ]

        // Act
        List<String> updatedLines = tool.updateBootstrapContentsWithKey(originalLines)
        logger.info("Updated bootstrap.conf lines: ${updatedLines}")

        // Assert
        assert updatedLines.size() == originalLines.size()
        assert updatedLines.first() == originalLines.first()
        assert updatedLines.last() == EXPECTED_KEY_LINE
    }

    @Test
    void testUpdateBootstrapContentsWithKeyShouldOverwriteExistingKey() {
        // Arrange
        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        tool.keyHex = KEY_HEX

        List<String> originalLines = [
                ConfigEncryptionTool.BOOTSTRAP_KEY_COMMENT,
                "${ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX}=badKey"
        ]

        // Act
        List<String> updatedLines = tool.updateBootstrapContentsWithKey(originalLines)
        logger.info("Updated bootstrap.conf lines: ${updatedLines}")

        // Assert
        assert updatedLines.size() == originalLines.size()
        assert updatedLines.first() == originalLines.first()
        assert updatedLines.last() == EXPECTED_KEY_LINE
    }

    @Test
    void testShouldUpdateBootstrapContentsWithKeyAndComment() {
        // Arrange
        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        tool.keyHex = KEY_HEX

        List<String> originalLines = [
                "${ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX}="
        ]

        // Act
        List<String> updatedLines = tool.updateBootstrapContentsWithKey(originalLines.clone() as List<String>)
        logger.info("Updated bootstrap.conf lines: ${updatedLines}")

        // Assert
        assert updatedLines.size() == originalLines.size() + 1
        assert updatedLines.first() == ConfigEncryptionTool.BOOTSTRAP_KEY_COMMENT
        assert updatedLines.last() == EXPECTED_KEY_LINE
    }

    @Test
    void testUpdateBootstrapContentsWithKeyShouldAddLines() {
        // Arrange
        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        tool.keyHex = KEY_HEX

        List<String> originalLines = []

        // Act
        List<String> updatedLines = tool.updateBootstrapContentsWithKey(originalLines.clone() as List<String>)
        logger.info("Updated bootstrap.conf lines: ${updatedLines}")

        // Assert
        assert updatedLines.size() == originalLines.size() + 3
        assert updatedLines.first() == "\n"
        assert updatedLines[1] == ConfigEncryptionTool.BOOTSTRAP_KEY_COMMENT
        assert updatedLines.last() == EXPECTED_KEY_LINE
    }

    @Test
    void testShouldWriteKeyToBootstrapConf() {
        // Arrange
        File emptyKeyFile = new File("src/test/resources/bootstrap_with_empty_master_key.conf")
        File workingFile = new File("tmp_bootstrap.conf")
        workingFile.delete()

        Files.copy(emptyKeyFile.toPath(), workingFile.toPath())
        final List<String> originalLines = workingFile.readLines()
        String originalKeyLine = originalLines.find { it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX) }
        logger.info("Original key line from bootstrap.conf: ${originalKeyLine}")

        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-b", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)

        // Act
        tool.writeKeyToBootstrapConf()
        logger.info("Updated bootstrap.conf")

        // Assert
        final List<String> updatedLines = workingFile.readLines()
        String updatedLine = updatedLines.find { it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX) }
        logger.info("Updated key line: ${updatedLine}")

        assert updatedLine == EXPECTED_KEY_LINE
        assert originalLines.size() == updatedLines.size()

        workingFile.deleteOnExit()
    }

    @Test
    void testWriteKeyToBootstrapConfShouldHandleReadFailure() {
        // Arrange
        File emptyKeyFile = new File("src/test/resources/bootstrap_with_empty_master_key.conf")
        File workingFile = new File("tmp_bootstrap.conf")
        workingFile.delete()

        Files.copy(emptyKeyFile.toPath(), workingFile.toPath())
        // Empty set of permissions
        Files.setPosixFilePermissions(workingFile.toPath(), [] as Set)
        logger.info("Set POSIX permissions to ${Files.getPosixFilePermissions(workingFile.toPath())}")

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-b", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)

        // Act
        def msg = shouldFail(IOException) {
            tool.writeKeyToBootstrapConf()
            logger.info("Updated bootstrap.conf")
        }
        logger.expected(msg)

        // Assert
        assert msg == "The bootstrap.conf file at tmp_bootstrap.conf must exist and be readable and writable by the user running this tool"

        workingFile.deleteOnExit()
    }

    @Test
    void testWriteKeyToBootstrapConfShouldHandleWriteFailure() {
        // Arrange
        File emptyKeyFile = new File("src/test/resources/bootstrap_with_empty_master_key.conf")
        File workingFile = new File("tmp_bootstrap.conf")
        workingFile.delete()

        Files.copy(emptyKeyFile.toPath(), workingFile.toPath())
        // Read-only set of permissions
        Files.setPosixFilePermissions(workingFile.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ] as Set)
        logger.info("Set POSIX permissions to ${Files.getPosixFilePermissions(workingFile.toPath())}")

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-b", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)

        // Act
        def msg = shouldFail(IOException) {
            tool.writeKeyToBootstrapConf()
            logger.info("Updated bootstrap.conf")
        }
        logger.expected(msg)

        // Assert
        assert msg == "The bootstrap.conf file at tmp_bootstrap.conf must exist and be readable and writable by the user running this tool"

        workingFile.deleteOnExit()
    }

    @Test
    void testShouldSerializeNiFiProperties() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/nifi_with_few_sensitive_properties_protected_aes.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath] as String[]

        String oldFilePath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        NiFiProperties properties = tool.loadNiFiProperties()
        logger.info("Loaded NiFiProperties from ${tool.niFiPropertiesPath}")
        logger.info("Loaded ${properties.size()} properties")

        // Act
        List<String> lines = ConfigEncryptionTool.serializeNiFiProperties(properties)
        logger.info("Serialized NiFiProperties to ${lines.size()} lines")
        logger.info("\n" + lines.join("\n"))

        // Assert

        // One extra line for the date
        assert lines.size() == properties.size() + 1
        assert lines.first() == "#${new Date().toString()}".toString()

        properties.keySet().every { String key ->
            assert lines.contains("${key}=${properties.getRawProperty(key)}".toString())
        }

        // The system variable was reset to the original value
        assert System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH) == oldFilePath
    }

    @Test
    void testShouldSerializeNiFiPropertiesAndPreserveFormat() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/nifi_with_few_sensitive_properties_protected_aes.properties"
        String originalNiFiPropertiesPath = "src/test/resources/nifi_with_few_sensitive_properties_unprotected.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath] as String[]

        // 3 properties are encrypted in the different files
        int protectedPropertyCount = 3

        String oldFilePath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        File originalFile = new File(originalNiFiPropertiesPath)
        List<String> originalLines = originalFile.readLines()
        logger.info("Read ${originalLines.size()} lines from ${originalNiFiPropertiesPath}")
        logger.info("\n" + originalLines[0..3].join("\n") + "...")

        NiFiProperties properties = tool.loadNiFiProperties()
        logger.info("Loaded NiFiProperties from ${tool.niFiPropertiesPath}")
        logger.info("Loaded ${properties.size()} properties")
        logger.info("There are ${protectedPropertyCount} sensitive properties that are protected that were not in the original")

        // Act
        List<String> lines = ConfigEncryptionTool.serializeNiFiPropertiesAndPreserveFormat(properties, originalFile)
        logger.info("Serialized NiFiProperties to ${lines.size()} lines")
        lines.eachWithIndex { String entry, int i ->
            logger.debug("${i.toString().padLeft(3)}: ${entry}")
        }

        // Assert

        // Added n new lines for the encrypted properties
        assert lines.size() == originalLines.size() + protectedPropertyCount

        properties.keySet().every { String key ->
            assert lines.contains("${key}=${properties.getRawProperty(key)}".toString())
        }

        logger.info("Updated nifi.properties:")
        logger.info("\n" * 2 + lines.join("\n"))

        // The system variable was reset to the original value
        assert System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH) == oldFilePath
    }

    @Test
    void testShouldSerializeNiFiPropertiesAndPreserveFormatWithNewPropertyAtEOF() {
        // Arrange
        String niFiPropertiesPath = "src/test/resources/nifi_with_few_sensitive_properties_protected_aes.properties"
        String originalNiFiPropertiesPath = "src/test/resources/nifi_with_few_sensitive_properties_unprotected.properties"
        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", niFiPropertiesPath, "-k", KEY_HEX] as String[]

        // 4 properties are encrypted in the different files
        int protectedPropertyCount = 4

        String oldFilePath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH)

        tool.parse(args)
        logger.info("Parsed nifi.properties location: ${tool.niFiPropertiesPath}")

        File originalFile = new File(originalNiFiPropertiesPath)
        List<String> originalLines = originalFile.readLines()
        logger.info("Read ${originalLines.size()} lines from ${originalNiFiPropertiesPath}")
        logger.info("\n" + originalLines[0..3].join("\n") + "...")

        NiFiProperties properties = tool.loadNiFiProperties()
        logger.info("Loaded NiFiProperties from ${tool.niFiPropertiesPath}")
        logger.info("Loaded ${properties.size()} properties")
        logger.info("There are ${protectedPropertyCount} sensitive properties that are protected that were not in the original")

        // Set a value for the sensitive property which is the last line in the file
        properties.setProperty(NiFiProperties.SECURITY_TRUSTSTORE_PASSWD, "thisIsABadTruststorePassword")
        properties = tool.encryptSensitiveProperties(properties)
        tool.@niFiProperties = properties

        // Act
        List<String> lines = ConfigEncryptionTool.serializeNiFiPropertiesAndPreserveFormat(properties, originalFile)
        logger.info("Serialized NiFiProperties to ${lines.size()} lines")
        lines.eachWithIndex { String entry, int i ->
            logger.debug("${i.toString().padLeft(3)}: ${entry}")
        }

        // Assert

        // Added n new lines for the encrypted properties
        assert lines.size() == originalLines.size() + protectedPropertyCount

        properties.keySet().every { String key ->
            assert lines.contains("${key}=${properties.getRawProperty(key)}".toString())
        }

        logger.info("Updated nifi.properties:")
        logger.info("\n" * 2 + lines.join("\n"))

        // The system variable was reset to the original value
        assert System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH) == oldFilePath
    }

    @Test
    void testShouldWriteNiFiProperties() {
        // Arrange
        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File workingFile = new File("tmp_nifi.properties")
        workingFile.delete()

        final List<String> originalLines = inputPropertiesFile.readLines()

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", inputPropertiesFile.path, "-o", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)
        NiFiProperties niFiProperties = tool.loadNiFiProperties()
        tool.@niFiProperties = niFiProperties
        logger.info("Loaded ${niFiProperties.size()} properties from ${inputPropertiesFile.path}")

        // Act
        tool.writeNiFiProperties()
        logger.info("Wrote to ${workingFile.path}")

        // Assert
        final List<String> updatedLines = workingFile.readLines()
        niFiProperties.keySet().every { String key ->
            assert updatedLines.contains("${key}=${niFiProperties.getRawProperty(key)}".toString())
        }

        assert originalLines == updatedLines

        logger.info("Updated nifi.properties:")
        logger.info("\n" * 2 + updatedLines.join("\n"))

        workingFile.deleteOnExit()
    }

    @Test
    void testWriteNiFiPropertiesShouldHandleWriteFailureWhenFileExists() {
        // Arrange
        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File workingFile = new File("tmp_nifi.properties")
        workingFile.delete()

        Files.copy(inputPropertiesFile.toPath(), workingFile.toPath())
        // Read-only set of permissions
        Files.setPosixFilePermissions(workingFile.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ] as Set)
        logger.info("Set POSIX permissions to ${Files.getPosixFilePermissions(workingFile.toPath())}")

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", inputPropertiesFile.path, "-o", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)
        NiFiProperties niFiProperties = tool.loadNiFiProperties()
        tool.@niFiProperties = niFiProperties
        logger.info("Loaded ${niFiProperties.size()} properties from ${inputPropertiesFile.path}")

        // Act
        def msg = shouldFail(IOException) {
            tool.writeNiFiProperties()
            logger.info("Wrote to ${workingFile.path}")
        }
        logger.expected(msg)

        // Assert
        assert msg == "The nifi.properties file at ${workingFile.path} must be writable by the user running this tool".toString()

        workingFile.deleteOnExit()
    }

    @Test
    void testWriteNiFiPropertiesShouldHandleWriteFailureWhenFileDoesNotExist() {
        // Arrange
        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File tmpDir = new File("tmp/")
        tmpDir.mkdirs()
        File workingFile = new File("tmp/tmp_nifi.properties")
        workingFile.delete()

        // Read-only set of permissions
        Files.setPosixFilePermissions(tmpDir.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ] as Set)
        logger.info("Set POSIX permissions on parent directory to ${Files.getPosixFilePermissions(tmpDir.toPath())}")

        ConfigEncryptionTool tool = new ConfigEncryptionTool()
        String[] args = ["-n", inputPropertiesFile.path, "-o", workingFile.path, "-k", KEY_HEX]
        tool.parse(args)
        NiFiProperties niFiProperties = tool.loadNiFiProperties()
        tool.@niFiProperties = niFiProperties
        logger.info("Loaded ${niFiProperties.size()} properties from ${inputPropertiesFile.path}")

        // Act
        def msg = shouldFail(IOException) {
            tool.writeNiFiProperties()
            logger.info("Wrote to ${workingFile.path}")
        }
        logger.expected(msg)

        // Assert
        assert msg == "The nifi.properties file at ${workingFile.path} must be writable by the user running this tool".toString()

        workingFile.deleteOnExit()
        Files.setPosixFilePermissions(tmpDir.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE] as Set)
        tmpDir.deleteOnExit()
    }

    @Test
    void testShouldPerformFullOperation() {
        // Arrange
        File tmpDir = new File("tmp/")
        tmpDir.mkdirs()
        Files.setPosixFilePermissions(tmpDir.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE] as Set)

        File emptyKeyFile = new File("src/test/resources/bootstrap_with_empty_master_key.conf")
        File bootstrapFile = new File("tmp/tmp_bootstrap.conf")
        bootstrapFile.delete()

        Files.copy(emptyKeyFile.toPath(), bootstrapFile.toPath())
        final List<String> originalBootstrapLines = bootstrapFile.readLines()
        String originalKeyLine = originalBootstrapLines.find {
            it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX)
        }
        logger.info("Original key line from bootstrap.conf: ${originalKeyLine}")
        assert originalKeyLine == ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX

        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + KEY_HEX

        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File outputPropertiesFile = new File("tmp/tmp_nifi.properties")
        outputPropertiesFile.delete()

        final List<String> originalPropertiesLines = inputPropertiesFile.readLines()

        String[] args = ["-n", inputPropertiesFile.path, "-b", bootstrapFile.path, "-o", outputPropertiesFile.path, "-k", KEY_HEX]

        // Act
        ConfigEncryptionTool.main(args)
        logger.info("Invoked #main with ${args.join(" ")}")

        // Assert
        final List<String> updatedPropertiesLines = outputPropertiesFile.readLines()
        logger.info("Updated nifi.properties:")
        logger.info("\n" * 2 + updatedPropertiesLines.join("\n"))

        // Check that the existing NiFiProperties matches the output file
        NiFiProperties niFiProperties = NiFiProperties.getInstance()
        niFiProperties.keySet().every { String key ->
            assert updatedPropertiesLines.contains("${key}=${niFiProperties.getRawProperty(key)}".toString())
        }

        // Check that the key was persisted to the bootstrap.conf
        final List<String> updatedBootstrapLines = bootstrapFile.readLines()
        String updatedKeyLine = updatedBootstrapLines.find { it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX) }
        logger.info("Updated key line: ${updatedKeyLine}")

        assert updatedKeyLine == EXPECTED_KEY_LINE
        assert originalBootstrapLines.size() == updatedBootstrapLines.size()

        // Clean up
        outputPropertiesFile.deleteOnExit()
        bootstrapFile.deleteOnExit()
        tmpDir.deleteOnExit()
    }

    @Test
    void testShouldPerformFullOperationWithPassword() {
        // Arrange
        File tmpDir = new File("tmp/")
        tmpDir.mkdirs()
        Files.setPosixFilePermissions(tmpDir.toPath(), [PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE] as Set)

        File emptyKeyFile = new File("src/test/resources/bootstrap_with_empty_master_key.conf")
        File bootstrapFile = new File("tmp/tmp_bootstrap.conf")
        bootstrapFile.delete()

        Files.copy(emptyKeyFile.toPath(), bootstrapFile.toPath())
        final List<String> originalBootstrapLines = bootstrapFile.readLines()
        String originalKeyLine = originalBootstrapLines.find {
            it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX)
        }
        logger.info("Original key line from bootstrap.conf: ${originalKeyLine}")
        assert originalKeyLine == ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX

        final String EXPECTED_KEY_HEX = ConfigEncryptionTool.deriveKeyFromPassword(PASSWORD)
        logger.info("Derived key from password [${PASSWORD}]: ${EXPECTED_KEY_HEX}")

        final String EXPECTED_KEY_LINE = ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX + EXPECTED_KEY_HEX

        File inputPropertiesFile = new File("src/test/resources/nifi_with_sensitive_properties_unprotected.properties")
        File outputPropertiesFile = new File("tmp/tmp_nifi.properties")
        outputPropertiesFile.delete()

        final List<String> originalPropertiesLines = inputPropertiesFile.readLines()

        String[] args = ["-n", inputPropertiesFile.path, "-b", bootstrapFile.path, "-o", outputPropertiesFile.path, "-p", PASSWORD]

        // Act
        ConfigEncryptionTool.main(args)
        logger.info("Invoked #main with ${args.join(" ")}")

        // Assert
        final List<String> updatedPropertiesLines = outputPropertiesFile.readLines()
        logger.info("Updated nifi.properties:")
        logger.info("\n" * 2 + updatedPropertiesLines.join("\n"))

        // Check that the existing NiFiProperties matches the output file
        NiFiProperties niFiProperties = NiFiProperties.getInstance()
        niFiProperties.keySet().every { String key ->
            assert updatedPropertiesLines.contains("${key}=${niFiProperties.getRawProperty(key)}".toString())
        }

        // Check that the key was persisted to the bootstrap.conf
        final List<String> updatedBootstrapLines = bootstrapFile.readLines()
        String updatedKeyLine = updatedBootstrapLines.find { it.startsWith(ConfigEncryptionTool.BOOTSTRAP_KEY_PREFIX) }
        logger.info("Updated key line: ${updatedKeyLine}")

        assert updatedKeyLine == EXPECTED_KEY_LINE
        assert originalBootstrapLines.size() == updatedBootstrapLines.size()

        // Clean up
        outputPropertiesFile.deleteOnExit()
        bootstrapFile.deleteOnExit()
        tmpDir.deleteOnExit()
    }
}

public class TestAppender extends AppenderBase<LoggingEvent> {
    static List<LoggingEvent> events = new ArrayList<>();

    @Override
    protected void append(LoggingEvent e) {
        events.add(e);
    }

    public static void reset() {
        events.clear();
    }
}