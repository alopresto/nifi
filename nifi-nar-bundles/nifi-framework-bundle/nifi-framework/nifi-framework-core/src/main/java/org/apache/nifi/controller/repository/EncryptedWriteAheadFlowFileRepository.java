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
package org.apache.nifi.controller.repository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.controller.queue.FlowFileQueue;
import org.apache.nifi.controller.repository.claim.ContentClaim;
import org.apache.nifi.controller.repository.claim.ResourceClaimManager;
import org.apache.nifi.security.kms.KeyProvider;
import org.apache.nifi.security.repository.RepositoryEncryptorUtils;
import org.apache.nifi.security.repository.RepositoryType;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.wali.SequentialAccessWriteAheadLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wali.MinimalLockingWriteAheadLog;
import org.wali.WriteAheadRepository;

/**
 * This class is an implementation of the {@link WriteAheadFlowFileRepository} flowfile repository which provides transparent
 * block encryption/decryption of flowfile attributes during file system interaction. As of Apache NiFi 1.11.0
 * (post-October 2019), this implementation is considered <a href="https://nifi.apache.org/docs/nifi-docs/html/user-guide.html#experimental-warning">*experimental*</a>. For further details, review the
 * <a href="https://nifi.apache.org/docs/nifi-docs/html/user-guide.html#encrypted-flowfile">Apache NiFi User Guide -
 * Encrypted FlowFile Repository</a> and
 * <a href="https://nifi.apache.org/docs/nifi-docs/html/administration-guide.html#encrypted-write-ahead-flowfile-repository-properties">Apache NiFi Admin Guide - Encrypted Write-Ahead FlowFile
 * Repository Properties</a>.
 *
 * <p>
 * Implements FlowFile Repository using WALI as the backing store which provides transparent encryption & decryption of the flowfile attributes.
 * </p>
 *
 * <p>
 * We expose a property named <code>nifi.flowfile.repository.always.sync</code>
 * that is a boolean value indicating whether or not to force WALI to sync with
 * disk on each update. By default, the value is <code>false</code>. This is
 * needed only in situations in which power loss is expected and not mitigated
 * by Uninterruptable Power Sources (UPS) or when running in an unstable Virtual
 * Machine for instance. Otherwise, we will flush the data that is written to
 * the Operating System and the Operating System will be responsible to flush
 * its buffers when appropriate. The Operating System can be configured to hold
 * only a certain buffer size or not to buffer at all, as well. When using a
 * UPS, this is generally not an issue, as the machine is typically notified
 * before dying, in which case the Operating System will flush the data to disk.
 * Additionally, most disks on enterprise servers also have battery backups that
 * can power the disks long enough to flush their buffers. For this reason, we
 * choose instead to not sync to disk for every write but instead sync only when
 * we checkpoint.
 * </p>
 */
public class EncryptedWriteAheadFlowFileRepository extends WriteAheadFlowFileRepository {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedWriteAheadFlowFileRepository.class);

    private String activeKeyId;
    private KeyProvider keyProvider;

    private static final List<RepositoryRecordType> NULL_DESTINATION_VALID_TYPES = Arrays.asList(RepositoryRecordType.DELETE, RepositoryRecordType.CONTENTMISSING, RepositoryRecordType.CLEANUP_TRANSIENT_CLAIMS);


    private WriteAheadRepository<RepositoryRecord> wal;


    /**
     * default no args constructor for service loading only.
     */
    public EncryptedWriteAheadFlowFileRepository() {
        super();
    }

    public EncryptedWriteAheadFlowFileRepository(final NiFiProperties nifiProperties) throws IOException {
        super(nifiProperties);
        logger.info("Configuring encrypted flowfile repository properties");

        // Initialize the encryption-specific fields
        this.keyProvider = RepositoryEncryptorUtils.validateAndBuildRepositoryKeyProvider(nifiProperties, RepositoryType.FLOWFILE);

        // Set active key ID
        setActiveKeyId(nifiProperties.getContentRepositoryEncryptionKeyId());
    }

    String getActiveKeyId() {
        return activeKeyId;
    }

    public void setActiveKeyId(String activeKeyId) {
        // Key must not be blank and key provider must make key available
        if (StringUtils.isNotBlank(activeKeyId) && keyProvider.keyExists(activeKeyId)) {
            this.activeKeyId = activeKeyId;
            logger.debug("Set active key ID to '" + activeKeyId + "'");
        } else {
            logger.warn("Attempted to set active key ID to '" + activeKeyId + "' but that is not a valid or available key ID. Keeping active key ID as '" + this.activeKeyId + "'");

        }
    }

    @Override
    public void initialize(final ResourceClaimManager claimManager) throws IOException {
        super.initialize(claimManager, new StandardRepositoryRecordSerdeFactory(claimManager));
        // TODO: Encryption-specific initialization?
    }



    @Override
    public void close() throws IOException {
        super.close();
        // TODO: Encryption-specific close?
    }




    private void updateRepository(final Collection<RepositoryRecord> records, final boolean sync) throws IOException {
        for (final RepositoryRecord record : records) {
            // Only some record types can have a null destination
            if (!NULL_DESTINATION_VALID_TYPES.contains(record.getType()) && record.getDestination() == null) {
                throw new IllegalArgumentException("Record " + record + " has no destination and Type is " + record.getType());
            }
        }

        // Partition records by whether or not their type is 'CLEANUP_TRANSIENT_CLAIMS'. We do this because we don't want to send
        // these types of records to the Write-Ahead Log.
        final Map<Boolean, List<RepositoryRecord>> partitionedRecords = records.stream()
                .collect(Collectors.partitioningBy(record -> record.getType() == RepositoryRecordType.CLEANUP_TRANSIENT_CLAIMS));

        List<RepositoryRecord> recordsForWal = partitionedRecords.get(Boolean.FALSE);
        if (recordsForWal == null) {
            recordsForWal = Collections.emptyList();
        }

        // TODO: Use custom EWAL implementation to encrypt each record before persisting

        // update the repository.
        final int partitionIndex = wal.update(recordsForWal, sync);
        updateContentClaims(records, partitionIndex);
    }

    /**
     * Swaps the FlowFiles that live on the given Connection out to disk, using
     * the specified Swap File and returns the number of FlowFiles that were
     * persisted.
     *
     * @param queue        queue to swap out
     * @param swapLocation location to swap to
     * @throws IOException ioe
     */
    @Override
    public void swapFlowFilesOut(final List<FlowFileRecord> swappedOut, final FlowFileQueue queue, final String swapLocation) throws IOException {
        final List<RepositoryRecord> repoRecords = new ArrayList<>();
        if (swappedOut == null || swappedOut.isEmpty()) {
            return;
        }

        // TODO: Encrypt flowfiles before writing to swap

        for (final FlowFileRecord swapRecord : swappedOut) {
            final RepositoryRecord repoRecord = new StandardRepositoryRecord(queue, swapRecord, swapLocation);
            repoRecords.add(repoRecord);
        }

        // TODO: We should probably update this to support bulk 'SWAP OUT' records. As-is, we have to write out a
        // 'SWAP OUT' record for each FlowFile, which includes the Update Type, FlowFile ID, swap file location, and Queue ID.
        // We could instead have a single record with Update Type of 'SWAP OUT' and just include swap file location, Queue ID,
        // and all FlowFile ID's.
        // update WALI to indicate that the records were swapped out.
        wal.update(repoRecords, true);

        synchronized (this.swapLocationSuffixes) {
            this.swapLocationSuffixes.add(normalizeSwapLocation(swapLocation));
        }

        logger.info("Successfully swapped out {} FlowFiles from {} to Swap File {}", swappedOut.size(), queue, swapLocation);
    }

    @Override
    public void swapFlowFilesIn(final String swapLocation, final List<FlowFileRecord> swapRecords, final FlowFileQueue queue) throws IOException {
        final List<RepositoryRecord> repoRecords = new ArrayList<>();

        // TODO: Decrypt flowfiles after reading from swap

        for (final FlowFileRecord swapRecord : swapRecords) {
            final StandardRepositoryRecord repoRecord = new StandardRepositoryRecord(queue, swapRecord);
            repoRecord.setSwapLocation(swapLocation);   // set the swap file to indicate that it's being swapped in.
            repoRecord.setDestination(queue);

            repoRecords.add(repoRecord);
        }

        updateRepository(repoRecords, true);

        synchronized (this.swapLocationSuffixes) {
            this.swapLocationSuffixes.remove(normalizeSwapLocation(swapLocation));
        }

        logger.info("Repository updated to reflect that {} FlowFiles were swapped in to {}", new Object[]{swapRecords.size(), queue});
    }


    private Optional<Collection<RepositoryRecord>> migrateFromSequentialAccessLog(final WriteAheadRepository<RepositoryRecord> toUpdate) throws IOException {
        final String recoveryDirName = nifiProperties.getProperty(FLOWFILE_REPOSITORY_DIRECTORY_PREFIX);
        final File recoveryDir = new File(recoveryDirName);
        if (!recoveryDir.exists()) {
            return Optional.empty();
        }

        final WriteAheadRepository<RepositoryRecord> recoveryWal = new SequentialAccessWriteAheadLog<>(recoveryDir, serdeFactory, this);
        logger.info("Encountered FlowFile Repository that was written using the Sequential Access Write Ahead Log. Will recover from this version.");


        // TODO: Encrypt records before persisting to new repository (or will normal write handle this?)

        final Collection<RepositoryRecord> recordList;
        try {
            recordList = recoveryWal.recoverRecords();
        } finally {
            recoveryWal.shutdown();
        }

        toUpdate.update(recordList, true);

        logger.info("Successfully recovered files from existing Write-Ahead Log and transitioned to new Write-Ahead Log. Will not delete old files.");

        final File journalsDir = new File(recoveryDir, "journals");
        deleteRecursively(journalsDir);

        final File checkpointFile = new File(recoveryDir, "checkpoint");
        if (!checkpointFile.delete() && checkpointFile.exists()) {
            logger.warn("Failed to delete old file {}; this file should be cleaned up manually", checkpointFile);
        }

        final File partialFile = new File(recoveryDir, "checkpoint.partial");
        if (!partialFile.delete() && partialFile.exists()) {
            logger.warn("Failed to delete old file {}; this file should be cleaned up manually", partialFile);
        }

        return Optional.of(recordList);
    }

    @SuppressWarnings("deprecation")
    private Optional<Collection<RepositoryRecord>> migrateFromMinimalLockingLog(final WriteAheadRepository<RepositoryRecord> toUpdate) throws IOException {
        final List<File> partitionDirs = new ArrayList<>();
        for (final File recoveryFile : recoveryFiles) {
            final File[] partitions = recoveryFile.listFiles(file -> file.getName().startsWith("partition-"));
            for (final File partition : partitions) {
                partitionDirs.add(partition);
            }
        }

        if (partitionDirs == null || partitionDirs.isEmpty()) {
            return Optional.empty();
        }

        logger.info("Encountered FlowFile Repository that was written using the 'Minimal Locking Write-Ahead Log'. "
                + "Will recover from this version and re-write the repository using the new version of the Write-Ahead Log.");

        final SortedSet<Path> paths = recoveryFiles.stream()
                .map(File::toPath)
                .collect(Collectors.toCollection(TreeSet::new));

        // TODO: Encrypt records before persisting to new repository (or will normal write handle this?)

        final Collection<RepositoryRecord> recordList;
        final MinimalLockingWriteAheadLog<RepositoryRecord> minimalLockingWal = new MinimalLockingWriteAheadLog<>(paths, partitionDirs.size(), serdeFactory, null);
        try {
            recordList = minimalLockingWal.recoverRecords();
        } finally {
            minimalLockingWal.shutdown();
        }

        toUpdate.update(recordList, true);

        // Delete the old repository
        logger.info("Successfully recovered files from existing Write-Ahead Log and transitioned to new implementation. Will now delete old files.");
        for (final File partitionDir : partitionDirs) {
            deleteRecursively(partitionDir);
        }

        for (final File recoveryFile : recoveryFiles) {
            final File snapshotFile = new File(recoveryFile, "snapshot");
            if (!snapshotFile.delete() && snapshotFile.exists()) {
                logger.warn("Failed to delete old file {}; this file should be cleaned up manually", snapshotFile);
            }

            final File partialFile = new File(recoveryFile, "snapshot.partial");
            if (!partialFile.delete() && partialFile.exists()) {
                logger.warn("Failed to delete old file {}; this file should be cleaned up manually", partialFile);
            }
        }

        return Optional.of(recordList);
    }

    @Override
    public long loadFlowFiles(final QueueProvider queueProvider) throws IOException {
        final Map<String, FlowFileQueue> queueMap = new HashMap<>();
        for (final FlowFileQueue queue : queueProvider.getAllQueues()) {
            queueMap.put(queue.getIdentifier(), queue);
        }
        serdeFactory.setQueueMap(queueMap);

        // Since we used to use the MinimalLockingWriteAheadRepository, we need to ensure that if the FlowFile
        // Repo was written using that impl, that we properly recover from the implementation.
        Collection<RepositoryRecord> recordList = wal.recoverRecords();

        final Set<String> recoveredSwapLocations = wal.getRecoveredSwapLocations();
        synchronized (this.swapLocationSuffixes) {
            recoveredSwapLocations.forEach(loc -> this.swapLocationSuffixes.add(normalizeSwapLocation(loc)));
            logger.debug("Recovered {} Swap Files: {}", swapLocationSuffixes.size(), swapLocationSuffixes);
        }

        // If we didn't recover any records from our write-ahead log, attempt to recover records from the other implementation
        // of the write-ahead log. We do this in case the user changed the "nifi.flowfile.repository.wal.impl" property.
        // In such a case, we still want to recover the records from the previous FlowFile Repository and write them into the new one.
        // Since these implementations do not write to the same files, they will not interfere with one another. If we do recover records,
        // then we will update the new WAL (with fsync()) and delete the old repository so that we won't recover it again.
        if (recordList == null || recordList.isEmpty()) {
            if (walImplementation.equals(SEQUENTIAL_ACCESS_WAL)) {
                // Configured to use Sequential Access WAL but it has no records. Check if there are records in
                // a MinimalLockingWriteAheadLog that we can recover.
                recordList = migrateFromMinimalLockingLog(wal).orElse(new ArrayList<>());
            } else {
                // Configured to use Minimal Locking WAL but it has no records. Check if there are records in
                // a SequentialAccess Log that we can recover.
                recordList = migrateFromSequentialAccessLog(wal).orElse(new ArrayList<>());
            }
        }

        serdeFactory.setQueueMap(null);

        for (final RepositoryRecord record : recordList) {
            final ContentClaim claim = record.getCurrentClaim();
            if (claim != null) {
                claimManager.incrementClaimantCount(claim.getResourceClaim());
            }
        }

        // Determine the next sequence number for FlowFiles
        int numFlowFilesMissingQueue = 0;
        long maxId = 0;
        for (final RepositoryRecord record : recordList) {
            final long recordId = serdeFactory.getRecordIdentifier(record);
            if (recordId > maxId) {
                maxId = recordId;
            }

            final FlowFileRecord flowFile = record.getCurrent();
            final FlowFileQueue queue = record.getOriginalQueue();
            if (queue == null) {
                numFlowFilesMissingQueue++;
            } else {
                queue.put(flowFile);
            }
        }

        // Set the AtomicLong to 1 more than the max ID so that calls to #getNextFlowFileSequence() will
        // return the appropriate number.
        flowFileSequenceGenerator.set(maxId + 1);
        logger.info("Successfully restored {} FlowFiles and {} Swap Files", recordList.size() - numFlowFilesMissingQueue, recoveredSwapLocations.size());
        if (numFlowFilesMissingQueue > 0) {
            logger.warn("On recovery, found {} FlowFiles whose queue no longer exists. These FlowFiles will be dropped.", numFlowFilesMissingQueue);
        }

        final Runnable checkpointRunnable = new Runnable() {
            @Override
            public void run() {
                try {
                    logger.info("Initiating checkpoint of FlowFile Repository");
                    final long start = System.nanoTime();
                    final int numRecordsCheckpointed = checkpoint();
                    final long end = System.nanoTime();
                    final long millis = TimeUnit.MILLISECONDS.convert(end - start, TimeUnit.NANOSECONDS);
                    logger.info("Successfully checkpointed FlowFile Repository with {} records in {} milliseconds", numRecordsCheckpointed, millis);
                } catch (final Throwable t) {
                    logger.error("Unable to checkpoint FlowFile Repository due to " + t.toString(), t);
                }
            }
        };

        checkpointFuture = checkpointExecutor.scheduleWithFixedDelay(checkpointRunnable, checkpointDelayMillis, checkpointDelayMillis, TimeUnit.MILLISECONDS);

        return maxId;
    }

}
