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

package org.apache.nifi.toolkit.tls.service.server

import org.apache.nifi.toolkit.tls.commandLine.CommandLineParseException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.BeforeClass
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class TlsCertificateAuthorityServiceCommandLineGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(TlsCertificateAuthorityServiceCommandLineGroovyTest.class)

    private final String TEST_SRC_DIR = "src/test/resources/"
    private final String DEFAULT_KEY_PAIR_ALGORITHM = "RSA"
    private final String DEFAULT_SIGNING_ALGORITHM = "SHA256WITHRSA"

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder()

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Test
    void testParseShouldRequireToken() {
        // Arrange
        TlsCertificateAuthorityServiceCommandLine cl = new TlsCertificateAuthorityServiceCommandLine()

        def args = "-t".split(" ") as String[]

        // Act
        def msg = shouldFail(CommandLineParseException) {
            cl.parse(args)
        }
        logger.expected(msg)

        // Assert
        assert msg == "Error parsing command line. (Missing argument for option: t)"
    }

    @Test
    void testValidateParametersShouldVerifyTokenMinLength() {
        // Arrange
        TlsCertificateAuthorityServiceCommandLine cl = new TlsCertificateAuthorityServiceCommandLine()

        (1..<cl.TOKEN_MIN_LENGTH).each { int length ->
            String token = "t" * length
            def args = "-t ${token}".split(" ") as String[]
            cl.parse(args)

            // Act
            def msg = shouldFail(IllegalArgumentException) {
                boolean parametersAreValid = cl.validateParameters()
                logger.unexpected("Token with length ${token.length()} is valid: ${parametersAreValid}")
            }
            logger.expected(msg)

            // Assert
            assert msg == "The provided token must be at least 16 characters"
        }
    }

    @Test
    void testValidateParametersShouldVerifyAcceptableToken() {
        // Arrange
        TlsCertificateAuthorityServiceCommandLine cl = new TlsCertificateAuthorityServiceCommandLine()

        String token = "t" * 16
        def args = "-t ${token}".split(" ") as String[]
        cl.parse(args)

        // Act
        boolean parametersAreValid = cl.validateParameters()
        logger.info("Token with length ${token.length()} is valid: ${parametersAreValid}")

        // Assert
        assert parametersAreValid
    }

    @Ignore("Token is not parsed from config.json yet")
    @Test
    void testValidateParametersShouldVerifyAcceptableTokenFromConfigJson() {
        // Arrange
        TlsCertificateAuthorityServiceCommandLine cl = new TlsCertificateAuthorityServiceCommandLine()

        String json = """{
    "token": "${"t" * 16}"
}"""

        File configJson = tmpDir.newFile("config.json")
        String configJsonPath = configJson.path

        configJson.write(json)
        logger.info("Wrote JSON to ${configJsonPath}: ${json}")

        def args = "--useConfigJson --configJsonIn ${configJsonPath}".split(" ") as String[]
        cl.parse(args)

        // Manually read the config JSON file to populate the other variables
        cl.createConfig()

        // Act
        boolean parametersAreValid = cl.validateParameters()
        logger.info("Token with length ${cl.getToken().length()} is valid: ${parametersAreValid}")

        // Assert
        assert parametersAreValid
    }
}
