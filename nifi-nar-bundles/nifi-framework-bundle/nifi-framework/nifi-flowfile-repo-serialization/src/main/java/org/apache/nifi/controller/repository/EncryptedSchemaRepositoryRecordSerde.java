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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import org.apache.nifi.controller.repository.claim.ResourceClaimManager;
import org.apache.nifi.stream.io.StreamUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Implement interface rather than extending and accept delegate serde as constructor arg -- composition over inheritence
public class EncryptedSchemaRepositoryRecordSerde extends SchemaRepositoryRecordSerde {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedSchemaRepositoryRecordSerde.class);
    private static final int MAX_ENCODING_VERSION = 2;

    // private final RecordSchema writeSchema = RepositoryRecordSchema.REPOSITORY_RECORD_SCHEMA_V2;
    // private final RecordSchema contentClaimSchema = ContentClaimSchema.CONTENT_CLAIM_SCHEMA_V1;
    //
    // private final ResourceClaimManager resourceClaimManager;
    // private volatile SchemaRecordReader reader;
    // private RecordIterator recordIterator = null;

    public EncryptedSchemaRepositoryRecordSerde(final ResourceClaimManager resourceClaimManager) {
        super(resourceClaimManager);
    }

    // @Override
    // public void writeHeader(final DataOutputStream out) throws IOException {
    //     writeSchema.writeTo(out);
    // }

    // @Override
    // public void serializeEdit(final RepositoryRecord previousRecordState, final RepositoryRecord newRecordState, final DataOutputStream out) throws IOException {
    //     serializeRecord(newRecordState, out);
    // }

    @Override
    public void serializeRecord(final RepositoryRecord record, final DataOutputStream out) throws IOException {
        // Create BAOS wrapped in DOS
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream tempDataStream = new DataOutputStream(byteArrayOutputStream);

        // final RecordSchema schema;
        // switch (record.getType()) {
        //     case CREATE:
        //     case UPDATE:
        //         schema = RepositoryRecordSchema.CREATE_OR_UPDATE_SCHEMA_V2;
        //         break;
        //     case CONTENTMISSING:
        //     case DELETE:
        //         schema = RepositoryRecordSchema.DELETE_SCHEMA_V2;
        //         break;
        //     case SWAP_IN:
        //         schema = RepositoryRecordSchema.SWAP_IN_SCHEMA_V2;
        //         break;
        //     case SWAP_OUT:
        //         schema = RepositoryRecordSchema.SWAP_OUT_SCHEMA_V2;
        //         break;
        //     default:
        //         throw new IllegalArgumentException("Received Repository Record with unknown Update Type: " + record.getType()); // won't happen.
        // }
        //
        // serializeRecord(record, out, schema, RepositoryRecordSchema.REPOSITORY_RECORD_SCHEMA_V2);

        super.serializeRecord(record, tempDataStream);
        tempDataStream.flush();
        byte[] plainSerializedBytes = byteArrayOutputStream.toByteArray();

        // Encrypt the byte[]
        // TODO Actually encrypt
        byte[] cipherBytes = Arrays.copyOf(plainSerializedBytes, plainSerializedBytes.length);
        Collections.reverse(Arrays.asList(cipherBytes));

        out.writeInt(cipherBytes.length);
        out.write(cipherBytes);
    }


    // protected void serializeRecord(final RepositoryRecord record, final DataOutputStream out, RecordSchema schema, RecordSchema repositoryRecordSchema) throws IOException {
    //     final RepositoryRecordFieldMap fieldMap = new RepositoryRecordFieldMap(record, schema, contentClaimSchema);
    //     final RepositoryRecordUpdate update = new RepositoryRecordUpdate(fieldMap, repositoryRecordSchema);
    //     new SchemaRecordWriter().writeRecord(update, out);
    // }

    // @Override
    // public void readHeader(final DataInputStream in) throws IOException {
    //     final RecordSchema recoverySchema = RecordSchema.readFrom(in);
    //     reader = SchemaRecordReader.fromSchema(recoverySchema);
    // }

    // @Override
    // public RepositoryRecord deserializeEdit(final DataInputStream in, final Map<Object, RepositoryRecord> currentRecordStates, final int version) throws IOException {
    //     final RepositoryRecord record = deserializeRecord(in, version);
    //     if (record != null) {
    //         return record;
    //     }
    //
    //     // deserializeRecord may return a null if there is no more data. However, when we are deserializing
    //     // an edit, we do so only when we know that we should have data. This is why the JavaDocs for this method
    //     // on the interface indicate that this method should never return null. As a result, if there is no data
    //     // available, we handle this by throwing an EOFException.
    //     throw new EOFException();
    // }

    @Override
    public RepositoryRecord deserializeRecord(final DataInputStream in, final int version) throws IOException {
        // Read encrypted bytes, decrypt, wrap in stream, delegate to super
        int encryptedRecordLength = in.readInt();
        if (encryptedRecordLength == -1) {
            return null;
        }

        byte[] cipherBytes = new byte[encryptedRecordLength];
        StreamUtils.fillBuffer(in, cipherBytes);

        // Decrypt the byte[]
        // TODO Actually decrypt
        byte[] plainSerializedBytes = Arrays.copyOf(cipherBytes, cipherBytes.length);
        Collections.reverse(Arrays.asList(plainSerializedBytes));

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(plainSerializedBytes);
        DataInputStream wrappedInputStream = new DataInputStream(byteArrayInputStream);

        return super.deserializeRecord(wrappedInputStream, version);
    }

    // private RepositoryRecord nextRecord() throws IOException {
    //     final Record record;
    //     try {
    //         record = recordIterator.next();
    //     } catch (final Exception e) {
    //         recordIterator.close();
    //         recordIterator = null;
    //         throw e;
    //     }
    //
    //     if (record == null) {
    //         return null;
    //     }
    //
    //     return createRepositoryRecord(record);
    // }

    // private RepositoryRecord createRepositoryRecord(final Record updateRecord) throws IOException {
    //     if (updateRecord == null) {
    //         // null may be returned by reader.readRecord() if it encounters end-of-stream
    //         return null;
    //     }
    //
    //     // Top level is always going to be a "Repository Record Update" record because we need a 'Union' type record at the
    //     // top level that indicates which type of record we have.
    //     final Record record = (Record) updateRecord.getFieldValue(RepositoryRecordSchema.REPOSITORY_RECORD_UPDATE_V2);
    //
    //     final String actionType = (String) record.getFieldValue(RepositoryRecordSchema.ACTION_TYPE_FIELD);
    //     final RepositoryRecordType recordType = RepositoryRecordType.valueOf(actionType);
    //     switch (recordType) {
    //         case CREATE:
    //             return createRecord(record);
    //         case CONTENTMISSING:
    //         case DELETE:
    //             return deleteRecord(record);
    //         case SWAP_IN:
    //             return swapInRecord(record);
    //         case SWAP_OUT:
    //             return swapOutRecord(record);
    //         case UPDATE:
    //             return updateRecord(record);
    //     }
    //
    //     throw new IOException("Found unrecognized Update Type '" + actionType + "'");
    // }


    // @SuppressWarnings("unchecked")
    // private StandardRepositoryRecord createRecord(final Record record) {
    //     final StandardFlowFileRecord.Builder ffBuilder = new StandardFlowFileRecord.Builder();
    //     ffBuilder.id((Long) record.getFieldValue(RepositoryRecordSchema.RECORD_ID));
    //     ffBuilder.entryDate((Long) record.getFieldValue(FlowFileSchema.ENTRY_DATE));
    //
    //     final Long lastQueueDate = (Long) record.getFieldValue(FlowFileSchema.QUEUE_DATE);
    //     final Long queueDateIndex = (Long) record.getFieldValue(FlowFileSchema.QUEUE_DATE_INDEX);
    //     ffBuilder.lastQueued(lastQueueDate, queueDateIndex);
    //
    //     final Long lineageStartDate = (Long) record.getFieldValue(FlowFileSchema.LINEAGE_START_DATE);
    //     final Long lineageStartIndex = (Long) record.getFieldValue(FlowFileSchema.LINEAGE_START_INDEX);
    //     ffBuilder.lineageStart(lineageStartDate, lineageStartIndex);
    //
    //     populateContentClaim(ffBuilder, record);
    //     ffBuilder.size((Long) record.getFieldValue(FlowFileSchema.FLOWFILE_SIZE));
    //
    //     ffBuilder.addAttributes((Map<String, String>) record.getFieldValue(FlowFileSchema.ATTRIBUTES));
    //
    //     final FlowFileRecord flowFileRecord = ffBuilder.build();
    //
    //     final String queueId = (String) record.getFieldValue(RepositoryRecordSchema.QUEUE_IDENTIFIER);
    //     final FlowFileQueue queue = getFlowFileQueue(queueId);
    //
    //     final StandardRepositoryRecord repoRecord = new StandardRepositoryRecord(queue, flowFileRecord);
    //     requireFlowFileQueue(repoRecord, queueId);
    //     return repoRecord;
    // }
    //
    // private void requireFlowFileQueue(final StandardRepositoryRecord repoRecord, final String queueId) {
    //     if (queueId == null || queueId.trim().isEmpty()) {
    //         logger.warn("{} does not have a Queue associated with it; this record will be discarded", repoRecord.getCurrent());
    //         repoRecord.markForAbort();
    //     } else if (repoRecord.getOriginalQueue() == null) {
    //         logger.warn("{} maps to unknown Queue {}; this record will be discarded", repoRecord.getCurrent(), queueId);
    //         repoRecord.markForAbort();
    //     }
    // }
    //
    // private void populateContentClaim(final StandardFlowFileRecord.Builder ffBuilder, final Record record) {
    //     final Object claimMap = record.getFieldValue(FlowFileSchema.CONTENT_CLAIM);
    //     if (claimMap == null) {
    //         return;
    //     }
    //
    //     final Record claimRecord = (Record) claimMap;
    //     final ContentClaim contentClaim = ContentClaimFieldMap.getContentClaim(claimRecord, resourceClaimManager);
    //     final Long offset = ContentClaimFieldMap.getContentClaimOffset(claimRecord);
    //
    //     ffBuilder.contentClaim(contentClaim);
    //     ffBuilder.contentClaimOffset(offset);
    // }
    //
    // private RepositoryRecord updateRecord(final Record record) {
    //     return createRecord(record);
    // }
    //
    // private RepositoryRecord deleteRecord(final Record record) {
    //     final Long recordId = (Long) record.getFieldValue(RepositoryRecordSchema.RECORD_ID_FIELD);
    //     final StandardFlowFileRecord.Builder ffBuilder = new StandardFlowFileRecord.Builder().id(recordId);
    //     final FlowFileRecord flowFileRecord = ffBuilder.build();
    //
    //     final StandardRepositoryRecord repoRecord = new StandardRepositoryRecord((FlowFileQueue) null, flowFileRecord);
    //     repoRecord.markForDelete();
    //     return repoRecord;
    // }
    //
    // private RepositoryRecord swapInRecord(final Record record) {
    //     final StandardRepositoryRecord repoRecord = createRecord(record);
    //     final String swapLocation = (String) record.getFieldValue(new SimpleRecordField(RepositoryRecordSchema.SWAP_LOCATION, FieldType.STRING, Repetition.EXACTLY_ONE));
    //     repoRecord.setSwapLocation(swapLocation);
    //
    //     final String queueId = (String) record.getFieldValue(RepositoryRecordSchema.QUEUE_IDENTIFIER);
    //     requireFlowFileQueue(repoRecord, queueId);
    //     return repoRecord;
    // }
    //
    // private RepositoryRecord swapOutRecord(final Record record) {
    //     final Long recordId = (Long) record.getFieldValue(RepositoryRecordSchema.RECORD_ID_FIELD);
    //     final String queueId = (String) record.getFieldValue(new SimpleRecordField(RepositoryRecordSchema.QUEUE_IDENTIFIER, FieldType.STRING, Repetition.EXACTLY_ONE));
    //     final String swapLocation = (String) record.getFieldValue(new SimpleRecordField(RepositoryRecordSchema.SWAP_LOCATION, FieldType.STRING, Repetition.EXACTLY_ONE));
    //     final FlowFileQueue queue = getFlowFileQueue(queueId);
    //
    //     final FlowFileRecord flowFileRecord = new StandardFlowFileRecord.Builder()
    //             .id(recordId)
    //             .build();
    //
    //     return new StandardRepositoryRecord(queue, flowFileRecord, swapLocation);
    // }
    //
    // @Override
    // public int getVersion() {
    //     return MAX_ENCODING_VERSION;
    // }
    //
    // @Override
    // public boolean isWriteExternalFileReferenceSupported() {
    //     return true;
    // }
    //
    // @Override
    // public void writeExternalFileReference(final File externalFile, final DataOutputStream out) throws IOException {
    //     new SchemaRecordWriter().writeExternalFileReference(out, externalFile);
    // }
    //
    // @Override
    // public boolean isMoreInExternalFile() throws IOException {
    //     return recordIterator != null && recordIterator.isNext();
    // }
}
