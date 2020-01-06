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

package org.apache.nifi.controller.repository

import org.apache.nifi.controller.queue.FlowFileQueue
import org.apache.nifi.controller.repository.claim.ResourceClaimManager
import org.apache.nifi.controller.repository.claim.StandardResourceClaimManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security


@RunWith(JUnit4.class)
class EncryptedSchemaRepositoryRecordSerdeTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedSchemaRepositoryRecordSerdeTest.class)

    public static final String TEST_QUEUE_IDENTIFIER = "testQueueIdentifier"

    private ResourceClaimManager claimManager
    private Map<String, FlowFileQueue> queueMap
    private FlowFileQueue flowFileQueue
    private ByteArrayOutputStream byteArrayOutputStream
    private DataOutputStream dataOutputStream

    private EncryptedSchemaRepositoryRecordSerde esrrs

    @Rule
    public TestName testName = new TestName()

    @BeforeClass
    static void setUpOnce() throws Exception {
        Security.addProvider(new BouncyCastleProvider())

        logger.metaClass.methodMissing = { String name, args ->
            logger.info("[${name?.toUpperCase()}] ${(args as List).join(" ")}")
        }
    }

    @Before
    void setUp() throws Exception {
        claimManager = new StandardResourceClaimManager()
        queueMap = [:]
        flowFileQueue = createAndRegisterMockQueue(TEST_QUEUE_IDENTIFIER)
        byteArrayOutputStream = new ByteArrayOutputStream()
        dataOutputStream = new DataOutputStream(byteArrayOutputStream)

        esrrs = new EncryptedSchemaRepositoryRecordSerde(claimManager)
        esrrs.setQueueMap(queueMap)
    }

    @After
    void tearDown() throws Exception {
        claimManager.purge()
        queueMap.clear()
    }

    private FlowFileQueue createMockQueue(String identifier = testName.methodName + new Date().toString()) {
        [getIdentifier: { ->
            logger.mock("Retrieving flowfile queue identifier: ${identifier}")
            identifier
        }] as FlowFileQueue
    }

    private FlowFileQueue createAndRegisterMockQueue(String identifier = testName.methodName + new Date().toString()) {
        FlowFileQueue queue = createMockQueue(identifier)
        queueMap.put(identifier, queue)
        queue
    }

    private RepositoryRecord buildCreateRecord(FlowFileQueue queue, Map<String, String> attributes = [:]) {
        StandardRepositoryRecord record = new StandardRepositoryRecord(queue)
        StandardFlowFileRecord.Builder ffrb = new StandardFlowFileRecord.Builder()
        ffrb.addAttributes([uuid: getMockUUID()] + attributes as Map<String, String>)
        record.setWorking(ffrb.build())
        record
    }

    private RepositoryRecord buildUpdateRecord(FlowFileQueue queue, Map<String, String> attributes = [:], FlowFileRecord originalRecord) {
        StandardRepositoryRecord record = new StandardRepositoryRecord(queue, originalRecord)
        StandardFlowFileRecord.Builder ffrb = new StandardFlowFileRecord.Builder()
        ffrb.addAttributes([uuid: getMockUUID()] + attributes as Map<String, String>)
        record.setWorking(ffrb.build())
        record
    }

    private String getMockUUID() {
        "${testName.methodName ?: "no_test"}@${new Date().format("mmssSSS")}" as String
    }

    /** This test ensures that the creation of a flowfile record is applied to the specified output stream correctly with encryption */
    @Test
    void testShouldSerializeAndDeserializeRecord() {
        // Arrange
        RepositoryRecord newRecord = buildCreateRecord(flowFileQueue, [id: "1", firstName: "Andy", lastName: "LoPresto"])
        DataOutputStream dos = dataOutputStream

        esrrs.writeHeader(dataOutputStream)

        // Act
        esrrs.serializeRecord(newRecord, dos)
        logger.info("Output stream: ${Hex.toHexString(byteArrayOutputStream.toByteArray())} ")

        // Assert
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))
        esrrs.readHeader(dis)
        RepositoryRecord deserializedRecord = esrrs.deserializeRecord(dis, 2)

        /* The records will not be identical, because the process of serializing/deserializing changes the application
         * of the delta data. The CREATE with a "current" record containing attributes becomes an UPDATE with an
         * "original" record containing attributes */

        logger.info("    Original record: ${newRecord.dump()}")
        logger.info("Deserialized record: ${deserializedRecord.dump()}")
        assert newRecord.type == RepositoryRecordType.CREATE
        assert deserializedRecord.type == RepositoryRecordType.UPDATE
        assert deserializedRecord.originalAttributes == newRecord.current.attributes
    }

    /** This test ensures that the creation of a flowfile record is applied to the specified output stream correctly */
    @Test
    void testShouldSerializeRecordForCreate() {
        // Arrange
        RepositoryRecord newRecord = buildCreateRecord(flowFileQueue, [id: "1", firstName: "Andy", lastName: "LoPresto"])
        DataOutputStream dos = dataOutputStream

        esrrs.writeHeader(dataOutputStream)

        // Act
        esrrs.serializeRecord(newRecord, dos)
        logger.info("Output stream: ${Hex.toHexString(byteArrayOutputStream.toByteArray())} ")

        // Assert
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))
        esrrs.readHeader(dis)
        RepositoryRecord deserializedRecord = esrrs.deserializeRecord(dis, 2)

        /* The records will not be identical, because the process of serializing/deserializing changes the application
         * of the delta data. The CREATE with a "current" record containing attributes becomes an UPDATE with an
         * "original" record containing attributes */

        logger.info("    Original record: ${newRecord.dump()}")
        logger.info("Deserialized record: ${deserializedRecord.dump()}")
        assert newRecord.type == RepositoryRecordType.CREATE
        assert deserializedRecord.type == RepositoryRecordType.UPDATE
        assert deserializedRecord.originalAttributes == newRecord.current.attributes
    }
}
