package org.apache.nifi.wali

import org.apache.nifi.properties.AESSensitivePropertyProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.slf4j.LoggerFactory
import org.wali.SerDe
import org.wali.SerDeFactory
import org.wali.SingletonSerDeFactory
import org.wali.UpdateType

import java.security.Security
import java.util.logging.Logger

import static org.junit.Assert.assertNotNull

class EncryptedSequentialAccessWriteAheadLogTest extends GroovyTestCase {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedSequentialAccessWriteAheadLogTest.class)

    private static final String KEY_128_HEX = "0123456789ABCDEFFEDCBA9876543210"
    private static final String KEY_256_HEX = KEY_128_HEX * 2
    private static final int IV_LENGTH = AESSensitivePropertyProvider.getIvLength()

    private final SerDe<EncryptableRecord> mockEncryptedSerDe
    private final EncryptedSequentialAccessWriteAheadLog<EncryptableRecord> encryptedWAL

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
        mockEncryptedSerDe = buildMockEncryptedSerDe()
        encryptedWAL = createWriteRepo(mockEncryptedSerDe)
    }

    @After
    void tearDown() throws Exception {

    }

    /** This test creates flowfile records, adds them to the repository, and then recovers them to ensure they were persisted */
    @Test
    void testShouldUpdateWithExternalFile() {
        // Arrange


        // Act


        // Assert


    }

    private SerDe<EncryptableRecord> buildMockEncryptedSerDe() {
        [:] as SerDe<EncryptableRecord>
    }

    private SequentialAccessWriteAheadLog<EncryptableRecord> createRecoveryRepo() throws IOException {
        final File targetDir = new File("target")
        final File storageDir = new File(targetDir, testName.getMethodName())

        final SerDe<EncryptableRecord> serde = buildMockEncryptedSerDe()
        final SerDeFactory<EncryptableRecord> serdeFactory = new SingletonSerDeFactory<>(serde)
        final SequentialAccessWriteAheadLog<EncryptableRecord> repo = new SequentialAccessWriteAheadLog<>(storageDir, serdeFactory)

        return repo
    }

    private SequentialAccessWriteAheadLog<EncryptableRecord> createWriteRepo() throws IOException {
        return createWriteRepo(buildMockEncryptedSerDe())
    }

    private SequentialAccessWriteAheadLog<EncryptableRecord> createWriteRepo(final SerDe<EncryptableRecord> serde) throws IOException {
        final File targetDir = new File("target")
        final File storageDir = new File(targetDir, testName.getMethodName())
        deleteRecursively(storageDir)
        assertTrue(storageDir.mkdirs())

        final SerDeFactory<EncryptableRecord> serdeFactory = new SingletonSerDeFactory<>(serde)
        final SequentialAccessWriteAheadLog<EncryptableRecord> repo = new SequentialAccessWriteAheadLog<>(storageDir, serdeFactory)

        final Collection<EncryptableRecord> recovered = repo.recoverRecords()
        assertNotNull(recovered)
        assertTrue(recovered.isEmpty())

        return repo
    }

    /**
     * POGO which is used as flowfile record entity for the test. 
     */
    private class EncryptableRecord {
        String id
        Map<String, String> props
        UpdateType updateType
        boolean isEncrypted = false
        String swapLocation
    }

    private class EncryptedSerDe implements SerDe<EncryptableRecord> {

        @Override
        void serializeEdit(EncryptableRecord previousRecordState, EncryptableRecord newRecordState, DataOutputStream out) throws IOException {

        }


        @Override
        void serializeRecord(EncryptableRecord record, DataOutputStream out) throws IOException {

        }


        @Override
        EncryptableRecord deserializeEdit(DataInputStream dataInputStream, Map<Object, EncryptableRecord> currentRecordStates, int version) throws IOException {
            return null
        }


        @Override
        EncryptableRecord deserializeRecord(DataInputStream dataInputStream, int version) throws IOException {
            return null
        }


        @Override
        Object getRecordIdentifier(EncryptableRecord record) {
            return null
        }


        @Override
        UpdateType getUpdateType(EncryptableRecord record) {
            return null
        }


        @Override
        String getLocation(EncryptableRecord record) {
            return null
        }


        @Override
        int getVersion() {
            return 0
        }
    }
}
