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
package org.apache.nifi.security.util.attributes


import org.apache.nifi.flowfile.FlowFile
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

@RunWith(JUnit4.class)
class AttributeMatchingServiceTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(AttributeMatchingServiceTest.class)

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
    void testShouldGetIndividualAttribute() {
        // Arrange
        final String ATTRIBUTE_NAME = "my_attr"

        def inputs = [ATTRIBUTE_NAME,
                      "  ${ATTRIBUTE_NAME}  "]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getIndividualAttribute(input)

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes.size() == 1
            assert resolvedAttributes.first() == ATTRIBUTE_NAME
        }
    }

    @Test
    void testShouldNotGetEmptyIndividualAttribute() {
        // Arrange
        def inputs = ["", "  \t\n "]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getIndividualAttribute(input)

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes.isEmpty()
        }
    }

    @Test
    void testShouldGetListAttributes() {
        // Arrange
        final List<String> EXPECTED_ATTRIBUTES = ["my_attr", "my_attr_2", "earlier_attr"]

        def inputs = [EXPECTED_ATTRIBUTES.join(","),
                      EXPECTED_ATTRIBUTES.collect { "  ${it}  " }.join(",")]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getListAttributes(input, ",")

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes == EXPECTED_ATTRIBUTES
        }
    }

    /**
     * This test ensures the method does not throw an exception on empty input. The returned list may contain {@code ""} empty elements, but the input to this method should never be empty because of {@link AttributeMatchingService#getAttributes()} filters that.
     */
    @Test
    void testGetListAttributesShouldHandleEmptyInputs() {
        // Arrange
        def inputs = ["", "  \t\n "]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getListAttributes(input, ",")

            // Assert
            assert resolvedAttributes instanceof List<String>
        }
    }

    @Test
    void testGetListAttributesShouldHandleBadInputs() {
        // Arrange
        final List<String> EXPECTED_ATTRIBUTES = ["my_attr", "my_attr_2", "earlier_attr"]

        def inputs = [EXPECTED_ATTRIBUTES.reverse().join(","),
                      EXPECTED_ATTRIBUTES.collect { "  ${it}  " }.join("/")]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getListAttributes(input, ",")

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes != EXPECTED_ATTRIBUTES
        }
    }

    @Test
    void testShouldGetRegexAttributes() {
        // Arrange
        final List<String> ALL_ATTRIBUTES = ["attr_a", "attrB", "earlier_attr", "my_attr", "my_attr_2", "otherAttr"]
        final List<String> EXPECTED_ATTRIBUTES = ["earlier_attr", "my_attr", "my_attr_2"]

        final FlowFile mockFlowFile = [
                getAttributes: { -> ALL_ATTRIBUTES.collectEntries { [it, it.toUpperCase()] } }
        ] as FlowFile

        def inputs = [".*_attr.*", ".*[ry]_attr.*", "my_attr|my_attr_2|earlier_attr"]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getRegexAttributes(input, mockFlowFile)

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes == EXPECTED_ATTRIBUTES
        }
    }

    @Test
    void testGetRegexAttributesShouldBeSorted() {
        // Arrange
        final List<String> ALL_ATTRIBUTES = ("z".."a")
        final List<String> EXPECTED_ATTRIBUTES = ["a", "b", "c"]

        final FlowFile mockFlowFile = [
                getAttributes: { -> ALL_ATTRIBUTES.collectEntries { [it, it.toUpperCase()] } }
        ] as FlowFile

        String input = "[abc]"

        // Act
        def resolvedAttributes = AttributeMatchingService.getRegexAttributes(input, mockFlowFile)

        // Assert
        assert resolvedAttributes instanceof List<String>
        assert resolvedAttributes == EXPECTED_ATTRIBUTES
    }

    @Test
    void testGetRegexAttributesShouldNotMatchOnPartials() {
        // Arrange
        final List<String> ALL_ATTRIBUTES = ["short_attr", "long_attribute"]

        final FlowFile mockFlowFile = [
                getAttributes: { -> ALL_ATTRIBUTES.collectEntries { [it, it.toUpperCase()] } }
        ] as FlowFile

        // Both of these patterns would be partial matches for "long_attribute", but not complete matches
        def inputs = [".*_attr", "attr"]

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getRegexAttributes(input, mockFlowFile)

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert !resolvedAttributes.contains("long_attribute")
        }
    }

    // TODO: Test partial matching pattern (failure)

    // TODO: Test null and empty input for #getAttributes

    @Test
    void testShouldDetectMatchAllPattern() {
        // Arrange
        def matchingInputs = [".*", "  .*  ", "(.*)", "[.]*"]

        // The purpose of the MUT is not to evaluate all regexes for equality to .*, it is to bypass expensive filtering by detecting shortcut patterns. Some complex patterns which match all inputs will still return false
        def nonmatchingInputs = ["[\\s\\S]*", "  .{0,}  "]

        // Act
        def matchingResults = matchingInputs.collect { String input ->
            AttributeMatchingService.isMatchAllPattern(input)
        }

        def nonmatchingResults = nonmatchingInputs.collect { String input ->
            AttributeMatchingService.isMatchAllPattern(input)
        }

        // Assert
        assert matchingResults.every()
        assert !nonmatchingResults.any()
    }

    @Test
    void testGetAttributesShouldHandleBadInputs() {
        // Arrange
        def inputs = [null, "", "    ", "\t", "\n"]

        final FlowFile mockFlowFile = [getAttributes: { -> [:] }] as FlowFile

        // Act
        inputs.each { String input ->
            def resolvedAttributes = AttributeMatchingService.getAttributes(input, AttributeMatchingStrategy.INDIVIDUAL, mockFlowFile)

            // Assert
            assert resolvedAttributes instanceof List<String>
            assert resolvedAttributes.isEmpty()
        }
    }
}
