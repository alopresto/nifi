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

package org.apache.nifi.toolkit.tls.v2.server

import org.apache.commons.cli.CommandLine
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.contrib.java.lang.system.ExpectedSystemExit
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class CAServerRunnerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(CAServerRunnerTest.class)

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder()

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none()

    private static final String TOKEN = "token" * 4

    @BeforeClass
    static void setUpOnce() {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() {
        super.setUp()

    }

    @After
    void tearDown() {

    }

    private static BufferedReader generateShutdownReader(int seconds = 10) {
        // One newline character per 5 second delay
        String delay = "\n" * (seconds / 5)
        new BufferedReader(new StringReader("${delay}stop\n"))
    }

    @Test
    void testParseShouldRequireToken() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String KEYSTORE_PATH = keystoreFile.path
        final String KEYSTORE_PASSWORD = "password" * 2

        CAServerRunner runner = new CAServerRunner()

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine tokenCL = runner.parse(args as String[])
        logger.info("Parsed command line from args: ${args}")

        def msg = shouldFail {
            CommandLine noTokenCL = runner.parse(new String[0])
        }
        logger.expected(msg)

        // Assert
        assert tokenCL.getOptionValue(CAServerRunner.TOKEN_ARG) == TOKEN
    }

    /**
     * Normal invocation (JKS keystore with password).
     */
    @Test
    void testShouldParseKeystoreArgs() {
        // Arrange
        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String KEYSTORE_PATH = keystoreFile.path
        final String KEYSTORE_PASSWORD = "password" * 2

        CAServerRunner runner = new CAServerRunner()

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine cl = runner.parse(args as String[])
        logger.info("Parsed command line from args: ${args}")

        // Assert
        assert cl.getOptionValue(CAServerRunner.KEYSTORE_PATH_ARG) == KEYSTORE_PATH
        assert cl.getOptionValue(CAServerRunner.KEYSTORE_PASSWORD_ARG) == KEYSTORE_PASSWORD
    }

    /**
     * Normal invocation (JKS keystore with password).
     */
    @Test
    void testParseShouldRequireExternalCAFilesIfKeystoreMissing() {
        // Arrange
        File certFile = tmpDir.newFile("cert.pem")
        final String CERT_PATH = certFile.path
        File keyFile = tmpDir.newFile("cert.key")
        final String KEY_PATH = keyFile.path

        CAServerRunner runner = new CAServerRunner()

        def args = "-c ${CERT_PATH} -K ${KEY_PATH} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Act
        CommandLine cl = runner.parse(args as String[])
        logger.info("Parsed command line from args: ${args}")

        // Assert
        assert cl.getOptionValue(CAServerRunner.EXTERNAL_CA_CERT_PATH_ARG) == CERT_PATH
        assert cl.getOptionValue(CAServerRunner.EXTERNAL_CA_KEY_PATH_ARG) == KEY_PATH

        assert !cl.getOptionValue(CAServerRunner.KEYSTORE_PATH_ARG)
        assert !cl.getOptionValue(CAServerRunner.KEYSTORE_PASSWORD_ARG)
    }

    /**
     * Normal invocation (JKS keystore with password).
     */
    @Test
    void testShouldStartAndShutdownServer() {
        // Arrange
        exit.expectSystemExitWithStatus(0)

        File keystoreFile = tmpDir.newFile("keystore.jks")
        final String KEYSTORE_PATH = keystoreFile.path
        final String KEYSTORE_PASSWORD = "password" * 2

        def args = "-k ${KEYSTORE_PATH} -P ${KEYSTORE_PASSWORD} -t ${TOKEN}".split(" ")
        logger.info("Running with args: ${args}")

        // Override the shutdown reader
        int runTime = 5
        CAServerRunner.shutdownReader = generateShutdownReader(runTime)
        logger.info("Configured server to run for ~ ${runTime} s")

        long start, stop
        exit.checkAssertionAfterwards({
            logger.info("Ran main() with args: ${args}")

            stop = System.nanoTime()
            logger.stop("${stop} | ${new Date(stop).format("HH:mm:ss.SSS")}")

            long executionTime = stop - start
            logger.info("Server ran for ${executionTime} ns (${executionTime / 1_000_000_000}) s")
            assert executionTime > runTime * 1_000_000_000
        })

        // Act
        start = System.nanoTime()
        logger.start("${start} | ${new Date(start).format("HH:mm:ss.SSS")}")

        CAServerRunner.main(args)

        // Assert

        // Assertions defined above
    }
}
