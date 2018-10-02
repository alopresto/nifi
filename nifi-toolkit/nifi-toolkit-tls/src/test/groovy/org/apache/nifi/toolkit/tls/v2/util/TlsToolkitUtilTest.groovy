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


import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class TlsToolkitUtilTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(TlsToolkitUtilTest.class)

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

    /**
     * Verifies that the passwords are the correct length and are different
     */
    @Test
    void testShouldGenerateRandomPassword() {
        // Arrange
        int times = 5
        logger.info("Running test ${times} times")

        def passwords = []

        // Act
        times.times { int i ->
            def password = TlsToolkitUtil.generateRandomPassword()
            logger.info("Generated password: ${password}")
            passwords << password
        }

        // Assert
        assert passwords.size() == times
        assert passwords.unique() == passwords
        assert passwords.every { it =~ /[\w+\/]{30}/ }
    }

    @Test
    void testShouldGenerateRandomPasswordOfDifferentLength() {
        // Arrange
        int times = 5
        logger.info("Running test ${times} times")

        int customLength = 60

        def passwords = []

        // Act
        times.times { int i ->
            def password = TlsToolkitUtil.generateRandomPassword(customLength)
            logger.info("Generated password: ${password}")
            passwords << password
        }

        // Assert
        assert passwords.size() == times
        assert passwords.unique() == passwords
        assert passwords.every { it =~ /[\w+\/]{${customLength}}/ }
    }

    @Test
    void testShouldEnforceMinimumLengthOfPassword() {
        // Arrange
        int customLength = 10

        // Act
        def msg = shouldFail() {
            def password = TlsToolkitUtil.generateRandomPassword(customLength)
            logger.info("Generated password: ${password}")
        }

        // Assert
        assert msg == "The requested password length (${customLength} chars) cannot be less than the minimum password length (16 chars)".toString()
    }
}
