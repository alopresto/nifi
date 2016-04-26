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
package org.apache.nifi.attribute.expression.language

import org.apache.nifi.attribute.expression.language.evaluation.QueryResult
import org.apache.nifi.attribute.expression.language.exception.AttributeExpressionLanguageException
import org.apache.nifi.expression.AttributeExpression
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@RunWith(JUnit4.class)
public class QueryGroovyTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(QueryGroovyTest.class)

    private static final Map<String, String> attributes = new HashMap<>()

    @BeforeClass
    public static void setUpOnce() throws Exception {
        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        // Some of these values are defined for testing (not-yet-implemented) double types
        attributes.put("maxLong", String.valueOf(Long.MAX_VALUE))
        attributes.put("oneInt", "1")
        attributes.put("oneDouble", "1.0")
        attributes.put("justOverOneDouble", "1.000001")
        attributes.put("twoInt", "2")
        attributes.put("twoDouble", "2.0")
        attributes.put("justOverTwoDouble", "2.000001")
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testShouldDivideByOneLong() {
        // Arrange
        logger.attributes(attributes)
        final Long EXPECTED_QUOTIENT = Long.MAX_VALUE

        // Act
        def queries = [
                divideByOneIntQuery: '${maxLong:toNumber():divide(${oneInt})}',
//                divideByOneDoubleQuery: '${maxLong:toNumber():divide(${oneDouble})}',
        ]

        // Assert
        queries.each { String queryName, String query ->
            logger.query(query)
            logger.expected(EXPECTED_QUOTIENT)
            logger.actual(evaluateExpression(query, attributes))
            assert verifyEquals(query, attributes, EXPECTED_QUOTIENT)
        }
    }

    @Test
    public void testShouldDivideByTwoLong() {
        // Arrange
        logger.attributes(attributes)
        final Long EXPECTED_QUOTIENT = Long.MAX_VALUE / 2

        // Act
        def queries = [
                divideByTwoIntQuery: '${maxLong:toNumber():divide(${twoInt})}',
//                divideByTwoDoubleQuery: '${maxLong:toNumber():divide(${twoDouble})}',
        ]

        // Assert
        queries.each { String queryName, String query ->
            logger.query(query)
            logger.expected(EXPECTED_QUOTIENT)
            logger.actual(evaluateExpression(query, attributes))
            assert verifyEquals(query, attributes, EXPECTED_QUOTIENT)
        }
    }

    /**
     This test fails because Long.MAX_VALUE / 2 * 2 => Long.MAX_VALUE in Java, while the double -> Long conversion during division in the expression language loses precision, and the multiplication results in Long.MAX_VALUE - 1.
     */
    @Test
    public void testShouldNotLosePrecision() {
        // Arrange
        logger.attributes(attributes)
        final Long EXPECTED_QUOTIENT = Long.MAX_VALUE / 2 * 2

        // Act
        def queries = [
                divideAndMultiplyQuery: '${maxLong:toNumber():divide(${twoInt}):multiply(${twoInt})}',
//                divideByTwoDoubleQuery: '${maxLong:toNumber():divide(${twoDouble}):multiply(${twoDouble})}',
        ]

        // Assert
        queries.each { String queryName, String query ->
            logger.query(query)
            logger.expected(EXPECTED_QUOTIENT)
            logger.actual(evaluateExpression(query, attributes))
            assert verifyEquals(query, attributes, EXPECTED_QUOTIENT)
        }
    }

    private static def evaluateExpression(final String expression, final Map<String, String> attributes = [:]) {
        final Query query = Query.compile(expression)
        final QueryResult<?> result = query.evaluate(attributes)
        result.getValue()
    }

    private static boolean verifyEquals(final String expression, final Map<String, String> attributes, final Object expectedResult) {
        boolean validExpression = false

        try {
            Query.validateExpression(expression, false)
            validExpression = true
        } catch (AttributeExpressionLanguageException e) {
        }

        boolean resultCorrect = String.valueOf(expectedResult) == Query.evaluateExpressions(expression, attributes, null)

        final Query query = Query.compile(expression)
        final QueryResult<?> result = query.evaluate(attributes)

        AttributeExpression.ResultType expectedResultType
        switch (expectedResult) {
            case Number:
                expectedResultType = AttributeExpression.ResultType.NUMBER
                break
            case Boolean:
                expectedResultType = AttributeExpression.ResultType.BOOLEAN
                break
            default:
                expectedResultType = AttributeExpression.ResultType.STRING
        }
        boolean returnTypeCorrect = result.getResultType() == expectedResultType

        boolean castResultCorrect = expectedResult == result.getValue()

        logger.info("Valid expression: ${validExpression} && result correct: ${resultCorrect} && return type correct: ${returnTypeCorrect} && cast result correct: ${castResultCorrect}")
        validExpression && resultCorrect && returnTypeCorrect && castResultCorrect
    }
}
