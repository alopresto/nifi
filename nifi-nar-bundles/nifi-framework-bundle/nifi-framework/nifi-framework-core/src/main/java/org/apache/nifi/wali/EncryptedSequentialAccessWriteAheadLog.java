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

package org.apache.nifi.wali;

import java.io.File;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wali.SerDeFactory;
import org.wali.SyncListener;

/**
 * <p>
 * This implementation of WriteAheadRepository provides the ability to write all updates to the
 * repository sequentially by writing to a single journal file. Serialization of data into bytes
 * happens outside of any lock contention and is done so using recycled byte buffers. As such,
 * we occur minimal garbage collection and the theoretical throughput of this repository is equal
 * to the throughput of the underlying disk itself.
 * </p>
 *
 * <p>
 * This implementation makes the assumption that only a single thread will ever issue updates for
 * a given Record at any one time. I.e., the implementation is thread-safe but cannot guarantee
 * that records are recovered correctly if two threads simultaneously update the write-ahead log
 * with updates for the same record.
 * </p>
 *
 * <p>
 * This implementation transparently encrypts the objects as they are persisted to the journal file.
 * </p>
 */
public class EncryptedSequentialAccessWriteAheadLog<T> extends SequentialAccessWriteAheadLog<T> {
    private static final Logger logger = LoggerFactory.getLogger(EncryptedSequentialAccessWriteAheadLog.class);
    private final SerDeFactory<T> serdeFactory = null;


    public EncryptedSequentialAccessWriteAheadLog(final File storageDirectory, final SerDeFactory<T> serdeFactory) throws IOException {
        this(storageDirectory, serdeFactory, SyncListener.NOP_SYNC_LISTENER);
    }

    public EncryptedSequentialAccessWriteAheadLog(final File storageDirectory, final SerDeFactory<T> serdeFactory, final SyncListener syncListener) throws IOException {
        super(storageDirectory, serdeFactory, syncListener);
    }
}
