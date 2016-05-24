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
package org.apache.nifi.controller

import org.apache.nifi.connectable.Connection
import org.apache.nifi.connectable.Position
import org.apache.nifi.connectable.Positionable
import org.apache.nifi.controller.serialization.FlowEncodingVersion
import org.apache.nifi.controller.serialization.FlowSynchronizer
import org.apache.nifi.encrypt.StringEncryptor
import org.apache.nifi.groups.ProcessGroup
import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@RunWith(JUnit4.class)
class StandardFlowSynchronizerTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(StandardFlowSynchronizerTest.class)

    private static final String NIFI_PROPERTIES_KEY = "nifi.properties.file.path"
    private static final String PREVIOUS_NIFI_PROPERTIES_PATH = System.getProperty(NIFI_PROPERTIES_KEY)

    private FlowSynchronizer flowSynchronizer
//    private StringEncryptor mockStringEncryptor = [
//            encrypt: { String plaintext -> plaintext?.reverse() },
//            decrypt: { String cipherText -> cipherText?.reverse() }
//    ] as StringEncryptor
    // This needs to go away immediately
    private StringEncryptor stringEncryptor = new StringEncryptor("PBEwithMD5andDES", "BC", "thisIsABadPassword")

    @BeforeClass
    public static void setUpOnce() throws Exception {
        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }

        System.setProperty(NIFI_PROPERTIES_KEY, "src/test/resources/nifi.properties")
    }

    @Before
    public void setUp() throws Exception {
        // Can't mock final class StringEncryptor
//        flowSynchronizer = new StandardFlowSynchronizer(mockStringEncryptor)
        flowSynchronizer = new StandardFlowSynchronizer(stringEncryptor)
    }

    @After
    public void tearDown() throws Exception {
    }

    @AfterClass
    public static void tearDownOnce() throws Exception {
        if (PREVIOUS_NIFI_PROPERTIES_PATH) {
            System.setProperty(NIFI_PROPERTIES_KEY, PREVIOUS_NIFI_PROPERTIES_PATH)
        }
    }

    private static def parseFlowXml(String xmlFlowPath = "src/test/resources/conf/scale-positions-flow-raw.xml") {
        def document = new XmlSlurper().parse(new File(xmlFlowPath))
        logger.info("Parsed XML document at ${xmlFlowPath}")
        document
    }

    @Test
    public void testSyncFromOldVersionShouldScaleAllPositionables() {
        // Arrange

        // Import the workflow
        /*

        - element at -400, -400
        - element at -400, 0
        - element at -400, 400
        - element at 0, -400
        - element at 0, 0
        - element at 0, 400
        - element at 400, -400
        - element at 400, 0
        - element at 400, 400

         */
//        def parsedDocument = parseFlowXml()
//        logger.xml(parsedDocument)
//
//        // Collect all positionable elements
//        def positionableElements = parsedDocument.rootGroup.depthFirst().findAll { it.name() in ["processor", "processGroup"] }*.collectEntries {
//            [(it.id): [x: it.position.@x, y: it.position.@y]]
//        }.collectEntries()
//        logger.xml("Positionables: ${positionableElements}")
//
//        logger.xml("Processors: ${parsedDocument.rootGroup.processor.findAll { it.name }*.name.join(", ")}")
//
//        FlowEncodingVersion encodingVersion = FlowEncodingVersion.parse(parsedDocument.'@encoding-version'.text())
//        logger.xml("Encoding version: ${encodingVersion}")
//
//        // Internal state model of the positionables/connections
//        List<Positionable> positionables = parsedDocument.rootGroup.depthFirst().findAll { it.name() == "processor" }
//        List<Connection> connections = parsedDocument.rootGroup.depthFirst().findAll { it.name() == "connection" }

        // Mock for now
        FlowEncodingVersion encodingVersion = FlowEncodingVersion.parse("0.7")

        Position positionA = new Position(0, 25)
        final Position ORIGINAL_A = new Position(positionA.x, positionA.y)
        Positionable mockProcessorA = [getPosition: { -> positionA }, setPosition: { Position p -> positionA = p }] as Positionable

        Position positionB = new Position(100, 25)
        final Position ORIGINAL_B = new Position(positionB.x, positionB.y)
        Positionable mockProcessorB = [getPosition: { -> positionB }, setPosition: { Position p -> positionB = p }] as Positionable

        def positionables = [mockProcessorA, mockProcessorB]

        List<Position> positionsAB = []
        final List<Position> ORIGINAL_AB = positionsAB.clone() as List<Position>
        Connection mockConnectionAB = [getBendPoints: { -> positionsAB as List<Position> }, setBendPoints: { List<Position> p -> positionsAB = p }] as Connection
        def connections = [mockConnectionAB]


        ProcessGroup rootGroup = [
                findAllPositionables: { ->
                    positionables as Set
                },
                findAllConnections  : { ->
                    connections
                }
        ] as ProcessGroup

        // Act
        (flowSynchronizer as StandardFlowSynchronizer).scaleRootGroup(rootGroup, encodingVersion)

        // Run the flow synchronizer

        // Assert
//        positionables.every {
//            def oldPosition = positionableElements.find { p -> p.key == it.id }?.value
//            logger.old("ID: ${it.id} | x: ${oldPosition.x} | y: ${oldPosition.y}")
//            logger.new("ID: ${it.id} | x: ${it.position.x} | y: ${it.position.y}")
//
//            assert xandYMovedInCorrectDirection(oldPosition.x.toDouble(), it.position.x, oldPosition.y.toDouble(), it.position.y)
//        }

        logger.info("A: old ${ORIGINAL_A} | new ${mockProcessorA.position}")
        logger.info("B: old ${ORIGINAL_B} | new ${mockProcessorB.position}")

        assert positionMovedInCorrectDirection(ORIGINAL_A, mockProcessorA.position)
        assert positionMovedInCorrectDirection(ORIGINAL_B, mockProcessorB.position)
        assert mockConnectionAB.getBendPoints() == ORIGINAL_AB

        // Check that all (non-zero) positions are greater
    }

    private static boolean positionMovedInCorrectDirection(Position oldPosition, Position newPosition) {
        axisMovedInCorrectDirection(oldPosition.x, newPosition.x) && axisMovedInCorrectDirection(oldPosition.y, newPosition.y)
    }

    private boolean xandYMovedInCorrectDirection(double oldX, double newX, double oldY, double newY) {
        axisMovedInCorrectDirection(oldX, newX) && axisMovedInCorrectDirection(oldY, newY)
    }

    private static boolean axisMovedInCorrectDirection(double old, double updated) {
        /*
        old is negative, updated should be a "larger" negative number
        old is positive, updated should be a "larger" positive number
        old is 0, updated should be 0
         */
        old < 0 ? updated < old : (old > 0 ? updated > old : updated == old)
    }

    @Test
    public void testShouldScaleAllPositionablesInFlow() {
        // Arrange

        // Import the workflow
        /*

        - process group
        - elements within process group

         */

        // Collect all positionable elements

        // Act

        // Run the flow synchronizer

        // Assert

        // Check that all (non-zero) positions are greater
    }
}
