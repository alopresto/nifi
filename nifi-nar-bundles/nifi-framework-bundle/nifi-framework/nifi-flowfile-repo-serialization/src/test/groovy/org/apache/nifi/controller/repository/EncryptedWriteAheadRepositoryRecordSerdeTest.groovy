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
class EncryptedWriteAheadRepositoryRecordSerdeTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedWriteAheadRepositoryRecordSerdeTest.class)

    public static final String TEST_QUEUE_IDENTIFIER = "testQueueIdentifier"

    private ResourceClaimManager claimManager
    private Map<String, FlowFileQueue> queueMap
    private FlowFileQueue flowFileQueue
    private ByteArrayOutputStream byteArrayOutputStream
    private DataOutputStream dataOutputStream

    private EncryptedWriteAheadRepositoryRecordSerde ewarrs

    private static final String KEY_128_HEX = "0123456789ABCDEFFEDCBA9876543210"
    private static final String KEY_256_HEX = KEY_128_HEX * 2

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

        ewarrs = new EncryptedWriteAheadRepositoryRecordSerde(claimManager)
        ewarrs.setQueueMap(queueMap)
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

    /** This test ensures that the creation of a flowfile record is applied to the specified output stream correctly */
    @Test
    void testShouldSerializeRecordForCreate() {
        // Arrange
        RepositoryRecord newRecord = buildCreateRecord(flowFileQueue, [id: "1", firstName: "Andy", lastName: "LoPresto"])
        DataOutputStream dos = dataOutputStream

        // Act
        ewarrs.serializeRecord(newRecord, dos)
        logger.info("Output stream: ${Hex.toHexString(byteArrayOutputStream.toByteArray())} ")

        // Assert
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))
        RepositoryRecord deserializedRecord = ewarrs.deserializeRecord(dis, 9)

        /* The records will not be identical, because the process of serializing/deserializing changes the application
         * of the delta data. The CREATE with a "current" record containing attributes becomes an UPDATE with an
         * "original" record containing attributes */

        logger.info("    Original record: ${newRecord.dump()}")
        logger.info("Deserialized record: ${deserializedRecord.dump()}")
        assert newRecord.type == RepositoryRecordType.CREATE
        assert deserializedRecord.type == RepositoryRecordType.UPDATE
        assert deserializedRecord.originalAttributes == newRecord.current.attributes
    }

    /** This test ensures that when manually serializing an edit from null to a new record, the simple value changes made to the flowfile record are applied to the specified output stream correctly */
    @Test
    void testShouldSerializeEditForCreate() {
        // Arrange
        RepositoryRecord initialRecord = null
        RepositoryRecord modifiedRecord = buildCreateRecord(flowFileQueue, [id: "1", firstName: "Andy", lastName: "LoPresto"])
        DataOutputStream dos = dataOutputStream

        // Act
        ewarrs.serializeEdit(initialRecord, modifiedRecord, dos)
        logger.info("Output stream: ${Hex.toHexString(byteArrayOutputStream.toByteArray())} ")

        // Assert
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))
        RepositoryRecord deserializedRecord = ewarrs.deserializeRecord(dis, 9)

        /* The records will not be identical, because the process of serializing/deserializing changes the application
         * of the delta data. The CREATE with a "current" record containing attributes becomes an UPDATE with an
         * "original" record containing attributes */

        logger.info("    Original record: ${modifiedRecord.dump()}")
        logger.info("Deserialized record: ${deserializedRecord.dump()}")
        assert modifiedRecord.type == RepositoryRecordType.CREATE
        assert deserializedRecord.type == RepositoryRecordType.UPDATE
        assert deserializedRecord.originalAttributes == modifiedRecord.current.attributes
    }

    /** This test ensures that the simple value changes made to the flowfile record are applied to the specified output stream correctly */
    @Test
    void testShouldSerializeEditForUpdate() {
        // Arrange
        RepositoryRecord initialState = buildCreateRecord(flowFileQueue, [id: "1", firstName: "Andy", lastName: "LoPresto"])
        RepositoryRecord modifiedState = buildUpdateRecord(flowFileQueue, [id: "1", firstName: "ydnA", lastName: "otserPoL"], initialState.current)
        DataOutputStream dos = dataOutputStream

        // Act
        ewarrs.serializeEdit(null, initialState, dos)
        ewarrs.serializeEdit(initialState, modifiedState, dos)
        dos.flush()
        logger.info("Output stream: ${Hex.toHexString(byteArrayOutputStream.toByteArray())} ")

        // Assert
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))
        RepositoryRecord deserializedCreateRecord = ewarrs.deserializeRecord(dis, 9)
        RepositoryRecord deserializedUpdateRecord = ewarrs.deserializeRecord(dis, 9)

        /* The records will not be identical, because the process of serializing/deserializing changes the application
         * of the delta data. The CREATE with a "current" record containing attributes becomes an UPDATE with an
         * "original" record containing attributes */

        logger.info("    Original record: ${initialState.dump()}")
        logger.info("    Modified record: ${modifiedState.dump()}")
        logger.info("Deserialized create record: ${deserializedCreateRecord.dump()}")
        logger.info("Deserialized update record: ${deserializedUpdateRecord.dump()}")

        assert initialState.type == RepositoryRecordType.CREATE
        assert modifiedState.type == RepositoryRecordType.UPDATE

        assert deserializedCreateRecord.type == RepositoryRecordType.UPDATE
        assert deserializedCreateRecord.originalAttributes == initialState.current.attributes

        assert deserializedUpdateRecord.type == RepositoryRecordType.UPDATE
        assert deserializedUpdateRecord.updatedAttributes == modifiedState.current.attributes
    }

    // TODO: Test serializeEdit for markedForAbort, DELETE, SWAP_OUT, SWAP_IN


//    static String formatHex(byte[] bytes, int byteBlockSize = 8, boolean caps = false) {
//        String hex = Hex.toHexString(bytes)
//        int position = 0
//        while (hex.length() > position && hex.length() > byteBlockSize) {
//            position += byteBlockSize
//            hex.i
//        }
//    }
}
