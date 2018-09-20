/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License") you may not use this file except in compliance with
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
package org.apache.nifi.processors.standard

import org.apache.nifi.security.util.attributes.AttributeMatchingStrategy
import org.apache.nifi.security.util.crypto.HashAlgorithm
import org.apache.nifi.security.util.crypto.HashService
import org.apache.nifi.util.MockFlowFile
import org.apache.nifi.util.TestRunner
import org.apache.nifi.util.TestRunners
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.Security

@RunWith(JUnit4.class)
class CryptographicHashAttributeTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CryptographicHashAttributeTest.class)


    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() throws Exception {
    }

    @After
    void tearDown() throws Exception {
    }

    /**
     * Resets the runner to the default state and applies provided configuration values.
     *
     * @param runner the test runner
     * @param algorithm the {@link HashAlgorithm} (default SHA-256)
     * @param attributeMatchingStrategy the {@link AttributeMatchingStrategy} (default Individual)
     * @param failWhenEmpty true if the processor should fail when all attributes are missing (default false)
     * @param allowPartialAttributes true if the processor should succeed when some attributes are missing (default true)
     */
    private static void resetRunner(TestRunner runner, HashAlgorithm algorithm = HashAlgorithm.SHA256, AttributeMatchingStrategy attributeMatchingStrategy = AttributeMatchingStrategy.INDIVIDUAL, boolean failWhenEmpty = false, boolean allowPartialAttributes = true) {
        runner.clearProperties()
        runner.clearProvenanceEvents()
        runner.clearTransferState()

        logger.info("Setting hash algorithm to ${algorithm.name}")
        runner.setProperty(CryptographicHashAttribute.HASH_ALGORITHM, algorithm.name)

        // Set the attribute matching strategy
        logger.info("Setting attribute matching to ${attributeMatchingStrategy.name}")
        runner.setProperty(CryptographicHashAttribute.ATTRIBUTE_MATCHING_STRATEGY, attributeMatchingStrategy.name)

        // Set the other required properties
        runner.setProperty(CryptographicHashAttribute.PARTIAL_ATTR_ROUTE_POLICY, allowPartialAttributes ? CryptographicHashAttribute.PartialAttributePolicy.ALLOW.name() : CryptographicHashAttribute.PartialAttributePolicy.PROHIBIT.name())
        runner.setProperty(CryptographicHashAttribute.FAIL_WHEN_EMPTY, failWhenEmpty.toString())
    }

    @Test
    void testShouldCalculateHashOfPresentAttribute() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username and date
        def attributes = [
                username: "alopresto",
                date    : new Date().format("YYYY-MM-dd HH:mm:ss.SSS Z")
        ]

        algorithms.each { HashAlgorithm algorithm ->
            final EXPECTED_USERNAME_HASH = HashService.hashValue(algorithm, attributes["username"])
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["username"]}) = ${EXPECTED_USERNAME_HASH}")
            final EXPECTED_DATE_HASH = HashService.hashValue(algorithm, attributes["date"])
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["date"]}) = ${EXPECTED_DATE_HASH}")

            // Reset the processor
            resetRunner(runner, algorithm)

            // Add the desired dynamic properties
            addDynamicPropertiesForHashAttributes(runner, attributes.keySet(), algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

            final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = successfulFlowfiles.first()
            String hashedUsername = flowFile.getAttribute("username_${algorithm.name}")
            logger.info("flowfile.username_${algorithm.name} = ${hashedUsername}")
            String hashedDate = flowFile.getAttribute("date_${algorithm.name}")
            logger.info("flowfile.date_${algorithm.name} = ${hashedDate}")

            assert hashedUsername == EXPECTED_USERNAME_HASH
            assert hashedDate == EXPECTED_DATE_HASH
        }
    }

    @Test
    void testShouldCalculateHashOfMissingAttribute() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username (empty string) and date (null)
        def attributes = [
                username: "",
                date    : null
        ]

        algorithms.each { HashAlgorithm algorithm ->
            final EXPECTED_USERNAME_HASH = HashService.hashValue(algorithm, attributes["username"])
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["username"]}) = ${EXPECTED_USERNAME_HASH}")
            final EXPECTED_DATE_HASH = null
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["date"]}) = ${EXPECTED_DATE_HASH}")

            // Reset the processor
            resetRunner(runner, algorithm)

            // Add the desired dynamic properties
            addDynamicPropertiesForHashAttributes(runner, attributes.keySet(), algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

            final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = successfulFlowfiles.first()
            String hashedUsername = flowFile.getAttribute("username_${algorithm.name}")
            logger.info("flowfile.username_${algorithm.name} = ${hashedUsername}")
            String hashedDate = flowFile.getAttribute("date_${algorithm.name}")
            logger.info("flowfile.date_${algorithm.name} = ${hashedDate}")

            assert hashedUsername == EXPECTED_USERNAME_HASH
            assert hashedDate == EXPECTED_DATE_HASH
        }
    }

    @Test
    void testShouldRouteToFailureOnProhibitedMissingAttribute() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username (empty string) and date (null)
        def attributes = [
                username: "",
                date    : null
        ]
        def attributeKeys = attributes.keySet()

        algorithms.each { HashAlgorithm algorithm ->
            final EXPECTED_USERNAME_HASH = HashService.hashValue(algorithm, attributes["username"])
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["username"]}) = ${EXPECTED_USERNAME_HASH}")
            final EXPECTED_DATE_HASH = null
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["date"]}) = ${EXPECTED_DATE_HASH}")

            // Reset the processor (set to fail if there are missing attributes)
            resetRunner(runner, algorithm, AttributeMatchingStrategy.INDIVIDUAL, false, false)

            // Add the desired dynamic properties
            addDynamicPropertiesForHashAttributes(runner, attributeKeys, algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 1)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 0)

            final List<MockFlowFile> failedFlowFiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_FAILURE)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = failedFlowFiles.first()
            logger.info("Failed flowfile has attributes ${flowFile.attributes}")
            attributeKeys.each { String missingAttribute ->
                flowFile.assertAttributeNotExists("${missingAttribute}_${algorithm.name}")
            }
        }
    }

    @Test
    void testShouldRouteToFailureOnEmptyAttributes() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username (empty string) and date (null)
        def attributes = [
                username: "",
                date    : null
        ]
        def attributeKeys = attributes.keySet()

        algorithms.each { HashAlgorithm algorithm ->
            // Reset the processor (set to fail when empty)
            resetRunner(runner, algorithm, AttributeMatchingStrategy.INDIVIDUAL, true, false)

            addDynamicPropertiesForHashAttributes(runner, attributeKeys, algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 1)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 0)

            final List<MockFlowFile> failedFlowFiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_FAILURE)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = failedFlowFiles.first()
            logger.info("Failed flowfile has attributes ${flowFile.attributes}")
            attributeKeys.each { String missingAttribute ->
                flowFile.assertAttributeNotExists("${missingAttribute}_${algorithm.name}")
            }
        }
    }

    /**
     * If no dynamic properties (i.e. "username_sha256") are defined, the flowfile should not be routed to failure if it doesn't have attributes.
     */
    @Test
    void testShouldNoteRouteToFailureOnEmptyAttributesIfNoDynamicPropertiesSet() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username (empty string) and date (null)
        def attributes = [
                username: "",
                date    : null
        ]
        def attributeKeys = attributes.keySet()

        algorithms.each { HashAlgorithm algorithm ->
            // Reset the processor (set to fail when empty)
            resetRunner(runner, algorithm, AttributeMatchingStrategy.INDIVIDUAL, true, false)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

            final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = successfulFlowfiles.first()
            logger.info("Successful flowfile has attributes ${flowFile.attributes}")
            attributeKeys.each { String missingAttribute ->
                flowFile.assertAttributeNotExists("${missingAttribute}_${algorithm.name}")
            }
        }
    }

    @Test
    void testShouldRouteToSuccessOnAllowPartial() {
        // Arrange
        def algorithms = HashAlgorithm.values()

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes for username (empty string) and date (null)
        def attributes = [
                username: ""
        ]
        def attributeKeys = attributes.keySet()

        algorithms.each { HashAlgorithm algorithm ->
            final EXPECTED_USERNAME_HASH = HashService.hashValue(algorithm, attributes["username"])
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["username"]}) = ${EXPECTED_USERNAME_HASH}")
            final EXPECTED_DATE_HASH = null
            logger.expected("${algorithm.name.padLeft(11)}(${attributes["date"]}) = ${EXPECTED_DATE_HASH}")

            // Reset the processor (set to allow partial attributes)
            resetRunner(runner, algorithm, AttributeMatchingStrategy.INDIVIDUAL, false, true)

            // Add the desired dynamic properties
            addDynamicPropertiesForHashAttributes(runner, attributeKeys, algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

            final List<MockFlowFile> successfulFlowFiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = successfulFlowFiles.first()
            logger.info("Successful flowfile has attributes ${flowFile.attributes}")
            attributeKeys.each { String attribute ->
                flowFile.assertAttributeExists("${attribute}_${algorithm.name}")
            }
        }
    }

    @Test
    void testShouldCalculateHashWithVariousCharacterEncodings() {
        // Arrange
        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes
        def attributes = [test_attribute: "apachenifi"]

        HashAlgorithm algorithm = HashAlgorithm.MD5

        List<Charset> charsets = [StandardCharsets.UTF_8, StandardCharsets.UTF_16, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE]

        final def EXPECTED_MD5_HASHES = [
                "utf_8"   : "a968b5ec1d52449963dcc517789baaaf",
                "utf_16"  : "b8413d18f7e64042bb0322a1cd61eba2",
                "utf_16be": "b8413d18f7e64042bb0322a1cd61eba2",
                "utf_16le": "91c3b67f9f8ae77156f21f271cc09121",
        ]
        EXPECTED_MD5_HASHES.each { k, hash ->
            logger.expected("MD5(${k.padLeft(9)}(${attributes["test_attribute"]})) = ${hash}")
        }

        charsets.each { Charset charset ->
            // Calculate the expected hash value given the character set
            final EXPECTED_HASH = HashService.hashValue(algorithm, attributes["test_attribute"], charset)
            logger.expected("${algorithm.name}(${attributes["test_attribute"]}, ${charset.name()}) = ${EXPECTED_HASH}")

            // Sanity check
            assert EXPECTED_HASH == EXPECTED_MD5_HASHES[translateEncodingToMapKey(charset.name())]

            // Reset the processor
            resetRunner(runner, algorithm)

            logger.info("Setting character set to ${charset.name()}")
            runner.setProperty(CryptographicHashAttribute.CHARACTER_SET, charset.name())

            // Add the desired dynamic properties
            addDynamicPropertiesForHashAttributes(runner, attributes.keySet(), algorithm.name)

            // Insert the attributes in the mock flowfile
            runner.enqueue(new byte[0], attributes)

            // Act
            runner.run(1)

            // Assert
            runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
            runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

            final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

            // Extract the generated attributes from the flowfile
            MockFlowFile flowFile = successfulFlowfiles.first()
            String hashedAttribute = flowFile.getAttribute("test_attribute_${algorithm.name}")
            logger.info("flowfile.test_attribute_${algorithm.name} = ${hashedAttribute}")

            assert hashedAttribute == EXPECTED_HASH
        }
    }

    private static void addDynamicPropertiesForHashAttributes(TestRunner runner, Set<String> attributeNames, String algorithmName) {
        attributeNames.each { String attr ->
            runner.setProperty("${attr}_${algorithmName}", attr)
        }
    }

    // TODO: Test setting dynamic property and required property to ensure attribute list is correct

    // Tests to handle legacy behavior of HashAttribute

    /**
     * Incoming Flowfile
     * attributes: [username: “alopresto”, role: “security”, email: “alopresto@apache.org”, git_account: “alopresto”]
     *
     * @param overrides any attributes to override
     * @return the attributes map
     */
    private static Map<String, String> getLegacyFlowfileAttributes(Map<String, String> overrides = [:]) {
        def defaults = [username   : "alopresto",
                        role       : "security",
                        email      : "alopresto@apache.org",
                        git_account: "alopresto"
        ]

        defaults + overrides
    }

    /**
     *    CHA Properties (Individual)
     *
     *    attribute_enumeration_style: “individual”
     *    (dynamic) username_sha256: “username”
     *    (dynamic) git_account_sha256: “git_account”
     *
     *    Behavior (Individual)
     *
     *    username_sha256 = git_account_sha256 = $(echo -n "alopresto" | shasum -a 256) = 600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23
     *
     *    Resulting Flowfile (Individual)
     *
     *    attributes: [username: “alopresto”, role: “security”, email: “alopresto@apache.org”, git_account: “alopresto”, username_sha256: “600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23”, git_account_sha256: “600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23"]
     */
    @Test
    void testShouldHandleIndividualAttribute() {
        // Arrange
        def algorithm = HashAlgorithm.SHA256
        def attributeMatching = AttributeMatchingStrategy.INDIVIDUAL

        String usernameHashAttribute = "username_sha256"
        String gitAccountHashAttribute = "git_account_sha256"

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes with known values
        def attributes = getLegacyFlowfileAttributes()

        final EXPECTED_USERNAME_HASH = HashService.hashValue(algorithm, attributes["username"])
        logger.expected("${algorithm.name.padLeft(11)}(${attributes["username"]}) = ${EXPECTED_USERNAME_HASH}")
        final EXPECTED_GIT_ACCOUNT_HASH = HashService.hashValue(algorithm, attributes["git_account"])
        logger.expected("${algorithm.name.padLeft(11)}(${attributes["git_account"]}) = ${EXPECTED_GIT_ACCOUNT_HASH}")

        // Set the algorithm
        resetRunner(runner, algorithm, attributeMatching, false, true)

        // Add the desired dynamic properties
        runner.setProperty(usernameHashAttribute, "username")
        runner.setProperty(gitAccountHashAttribute, "git_account")

        // Insert the attributes in the mock flowfile
        runner.enqueue(new byte[0], attributes)

        // Act
        runner.run(1)

        // Assert
        runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
        runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

        final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

        // Extract the generated attributes from the flowfile
        MockFlowFile flowFile = successfulFlowfiles.first()
        String hashedUsername = flowFile.getAttribute(usernameHashAttribute)
        logger.info("flowfile.${usernameHashAttribute} = ${hashedUsername}")
        String hashedGitAccount = flowFile.getAttribute(gitAccountHashAttribute)
        logger.info("flowfile.${gitAccountHashAttribute} = ${hashedGitAccount}")

        assert hashedUsername == EXPECTED_USERNAME_HASH
        assert hashedGitAccount == EXPECTED_GIT_ACCOUNT_HASH
    }

    /**
     *    CHA Properties (List)
     *
     *    attribute_enumeration_style: “list”
     *    (dynamic) username_and_email_sha256: “username, email”
     *    (dynamic) git_account_sha256: “git_account”
     *
     *    Behavior (List)
     *
     *    username_and_email_sha256 = $(echo -n "aloprestoalopresto@apache.org" | shasum -a 256) = 22a11b7b3173f95c23a1f434949ec2a2e66455b9cb26b7ebc90afca25d91333f
     *    git_account_sha256 = $(echo -n "alopresto" | shasum -a 256) = 600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23
     *
     *    Resulting Flowfile (List)
     *
     *    attributes: [username: “alopresto”, role: “security”, email: “alopresto@apache.org”, git_account: “alopresto”, username_email_sha256: “ 22a11b7b3173f95c23a1f434949ec2a2e66455b9cb26b7ebc90afca25d91333f”, git_account_sha256: “600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23”]
     */
    @Test
    void testShouldHandleListAttributes() {
        // Arrange
        def algorithm = HashAlgorithm.SHA256
        def attributeMatching = AttributeMatchingStrategy.LIST

        String usernameAndEmailHashAttribute = "username_and_email_sha256"
        String gitAccountHashAttribute = "git_account_sha256"

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes with known values
        def attributes = getLegacyFlowfileAttributes()

        def usernameAndEmail = attributes["username"] + attributes["email"]
        final EXPECTED_USERNAME_AND_EMAIL_HASH = HashService.hashValue(algorithm, usernameAndEmail)
        logger.expected("${algorithm.name.padLeft(11)}(${usernameAndEmail}) = ${EXPECTED_USERNAME_AND_EMAIL_HASH}")
        final EXPECTED_GIT_ACCOUNT_HASH = HashService.hashValue(algorithm, attributes["git_account"])
        logger.expected("${algorithm.name.padLeft(11)}(${attributes["git_account"]}) = ${EXPECTED_GIT_ACCOUNT_HASH}")

        // Set the algorithm
        resetRunner(runner, algorithm, attributeMatching, false, true)

        // Add the desired dynamic properties
        runner.setProperty(usernameAndEmailHashAttribute, "username, email")
        runner.setProperty(gitAccountHashAttribute, "git_account")

        // Insert the attributes in the mock flowfile
        runner.enqueue(new byte[0], attributes)

        // Act
        runner.run(1)

        // Assert
        runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
        runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

        final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

        // Extract the generated attributes from the flowfile
        MockFlowFile flowFile = successfulFlowfiles.first()
        String hashedUsernameAndEmail = flowFile.getAttribute(usernameAndEmailHashAttribute)
        logger.info("flowfile.${usernameAndEmailHashAttribute} = ${hashedUsernameAndEmail}")
        String hashedGitAccount = flowFile.getAttribute(gitAccountHashAttribute)
        logger.info("flowfile.${gitAccountHashAttribute} = ${hashedGitAccount}")

        assert hashedUsernameAndEmail == EXPECTED_USERNAME_AND_EMAIL_HASH
        assert hashedGitAccount == EXPECTED_GIT_ACCOUNT_HASH
    }

    /**
     * CHA Properties (Regex)
     *
     * attribute_enumeration_style: “regex”
     * (dynamic) all_sha256: “.*”
     * (dynamic) git_account_sha256: “git_account”
     *
     * Behavior (Regex)
     *
     * all_sha256 = sort(attributes_that_match_regex) = [email, git_account, role, username] = $(echo -n "alopresto@apache.orgaloprestosecurityalopresto" | shasum -a 256) = b370fdf0132933cea76e3daa3d4a437bb8c571dd0cd0e79ee5d7759cf64efced
     * git_account_sha256 = $(echo -n "alopresto" | shasum -a 256) = 600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23
     *
     * Resulting Flowfile (Regex)
     *
     * attributes: [username: “alopresto”, role: “security”, email: “alopresto@apache.org”, git_account: “alopresto”, all_sha256: “ b370fdf0132933cea76e3daa3d4a437bb8c571dd0cd0e79ee5d7759cf64efced”, git_account_sha256: “600973dc8f2b7bb2a20651ebefe4bf91c5295afef19f4d5b9994d581f5a68a23”]
     */
    @Test
    void testShouldHandleRegexAttributes() {
        // Arrange
        def algorithm = HashAlgorithm.SHA256
        def attributeMatching = AttributeMatchingStrategy.REGEX

        String allHashAttribute = "all_sha256"
        String gitAccountHashAttribute = "git_account_sha256"

        final TestRunner runner = TestRunners.newTestRunner(new CryptographicHashAttribute())

        // Create attributes with known values
        def attributes = getLegacyFlowfileAttributes()

        def allAttributes = ["email", "git_account", "role", "username"]
        def all = allAttributes.collect { attributes[it] }.join()
        final EXPECTED_ALL_HASH = HashService.hashValue(algorithm, all)
        logger.expected("${algorithm.name.padLeft(11)}(${all}) = ${EXPECTED_ALL_HASH}")
        final EXPECTED_GIT_ACCOUNT_HASH = HashService.hashValue(algorithm, attributes["git_account"])
        logger.expected("${algorithm.name.padLeft(11)}(${attributes["git_account"]}) = ${EXPECTED_GIT_ACCOUNT_HASH}")

        // Set the algorithm
        resetRunner(runner, algorithm, attributeMatching, false, true)

        // Add the desired dynamic properties
        runner.setProperty(allHashAttribute, allAttributes.join("|"))
        runner.setProperty(gitAccountHashAttribute, "git_account")

        // Insert the attributes in the mock flowfile
        runner.enqueue(new byte[0], attributes)

        // Act
        runner.run(1)

        // Assert
        runner.assertTransferCount(CryptographicHashAttribute.REL_FAILURE, 0)
        runner.assertTransferCount(CryptographicHashAttribute.REL_SUCCESS, 1)

        final List<MockFlowFile> successfulFlowfiles = runner.getFlowFilesForRelationship(CryptographicHashAttribute.REL_SUCCESS)

        // Extract the generated attributes from the flowfile
        MockFlowFile flowFile = successfulFlowfiles.first()
        String hashedAll = flowFile.getAttribute(allHashAttribute)
        logger.info("flowfile.${allHashAttribute} = ${hashedAll}")
        String hashedGitAccount = flowFile.getAttribute(gitAccountHashAttribute)
        logger.info("flowfile.${gitAccountHashAttribute} = ${hashedGitAccount}")

        assert hashedAll == EXPECTED_ALL_HASH
        assert hashedGitAccount == EXPECTED_GIT_ACCOUNT_HASH
    }

    static String translateEncodingToMapKey(String charsetName) {
        charsetName.toLowerCase().replaceAll(/[-\/]/, '_')
    }
}
