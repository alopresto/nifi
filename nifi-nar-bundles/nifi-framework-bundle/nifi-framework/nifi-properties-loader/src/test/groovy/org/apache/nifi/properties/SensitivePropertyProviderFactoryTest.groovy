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
package org.apache.nifi.properties

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
class SensitivePropertyProviderFactoryTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(SensitivePropertyProviderFactoryTest.class)

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

    }

    @Test
    public void testShouldRegisterProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        assert factory.getAvailableProviderCount() == 0

        // Act
        boolean registered = factory.registerProvider(AESSensitivePropertyProvider.class)

        // Assert
        assert registered
        assert factory.getAvailableProviderCount() == 1
    }

    @Test
    public void testShouldHandleRegisterWithExistingKey() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        factory.registerProvider(AESSensitivePropertyProvider.class)
        assert factory.getAvailableProviderCount() == 1

        // Act
        boolean registered = factory.registerProvider(DuplicateAESProvider.class)

        // Assert
        assert !registered
        assert factory.getAvailableProviderCount() == 1
    }

    @Test
    public void testShouldHandleRegisterWithExistingKeyAndSameProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        factory.registerProvider(AESSensitivePropertyProvider.class)
        assert factory.getAvailableProviderCount() == 1

        // Act
        boolean registered = factory.registerProvider(AESSensitivePropertyProvider.class)

        // Assert
        assert !registered
        assert factory.getAvailableProviderCount() == 1
    }

    @Test
    public void testShouldHandleRegisterNullProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        assert factory.getAvailableProviderCount() == 0

        // Act
        def msg = shouldFail(IllegalArgumentException) {
            boolean registered = factory.registerProvider(null)
        }

        // Assert
        assert msg == "Cannot register a null SensitivePropertyProvider"
        assert factory.getAvailableProviderCount() == 0
    }

    @Test
    public void testShouldHandleRegisterInvalidProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        assert factory.getAvailableProviderCount() == 0

        // Act
        def msg = shouldFail(SensitivePropertyProtectionException) {
            boolean registered = factory.registerProvider(NoKeyProvider.class)
        }

        // Assert
        assert msg =~ "Could not register"
        assert factory.getAvailableProviderCount() == 0
    }

    @Test
    public void testConstructorShouldHandleEmptyProviders() throws Exception {
        // Arrange
        def providers = []

        // Act
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory(providers)

        // Assert
        assert factory.getAvailableProviderCount() == 0
    }

    @Test
    public void testConstructorShouldRegisterProviders() throws Exception {
        // Arrange
        def providers = [AESSensitivePropertyProvider.class, DistinctProvider.class]

        // Act
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory(providers)

        // Assert
        assert factory.getAvailableProviderCount() == 2
    }

    @Test
    public void testEmptyFactoryShouldNotHaveProviderAvailable() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        assert factory.getAvailableProviderCount() == 0

        // Act
        boolean isAvailable = factory.isProviderAvailable(new AESSensitivePropertyProvider().identifierKey)

        // Assert
        assert !isAvailable
    }

    @Test
    public void testProviderShouldBeAvailable() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        factory.registerProvider(AESSensitivePropertyProvider.class)
        assert factory.getAvailableProviderCount() == 1

        // Act
        boolean isAvailable = factory.isProviderAvailable(new AESSensitivePropertyProvider().identifierKey)

        // Assert
        assert isAvailable
    }

    @Test
    public void testEmptyFactoryShouldHandleGetProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        assert factory.getAvailableProviderCount() == 0
        final String KEY = new AESSensitivePropertyProvider().identifierKey
        assert !factory.isProviderAvailable(KEY)

        // Act
        def msg = shouldFail() {
            SensitivePropertyProvider provider = factory.getProvider(KEY)
        }

        // Assert
        assert msg =~ "No provider available for "
    }

    @Test
    public void testShouldGetProvider() throws Exception {
        // Arrange
        SensitivePropertyProviderFactory factory = new SensitivePropertyProviderFactory()
        factory.registerProvider(AESSensitivePropertyProvider.class)
        assert factory.getAvailableProviderCount() == 1
        final String KEY = new AESSensitivePropertyProvider().identifierKey
        assert factory.isProviderAvailable(KEY)

        // Act
        SensitivePropertyProvider provider = factory.getProvider(KEY)

        // Assert
        assert provider instanceof AESSensitivePropertyProvider
    }
}

public class DuplicateAESProvider extends AESSensitivePropertyProvider {
    public DuplicateAESProvider() { super() }

    @Override
    String getName() {
        return "DuplicateAESProvider"
    }

    @Override
    String getIdentifierKey() {
        return Object.getIdentifierKey()
    }
}

public class NoKeyProvider extends AESSensitivePropertyProvider {
    public NoKeyProvider() { super() }

    @Override
    String getName() {
        return "NoKeyProvider"
    }

    @Override
    String getIdentifierKey() {
        throw new InstantiationException();
    }
}

public class DistinctProvider extends AESSensitivePropertyProvider {
    public DistinctProvider() { super() }

    @Override
    String getName() {
        return "DistinctProvider"
    }

    @Override
    String getIdentifierKey() {
        return "distinct"
    }
}