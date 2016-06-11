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
package org.apache.nifi.properties;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESSensitivePropertyProviderFactory implements SensitivePropertyProviderFactory {
    private static final Logger logger = LoggerFactory.getLogger(AESSensitivePropertyProviderFactory.class);

    private String keyHex;

    public AESSensitivePropertyProviderFactory() {
    }

    public AESSensitivePropertyProviderFactory(String keyHex) {
        this.keyHex = keyHex;
    }

    public SensitivePropertyProvider getProvider() throws SensitivePropertyProtectionException {
        try {
            return new AESSensitivePropertyProvider(keyHex);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            String msg = "Error creating " + new AESSensitivePropertyProvider().getName();
            logger.warn(msg, e);
            throw new SensitivePropertyProtectionException(msg, e);
        }
    }

    @Override
    public String toString() {
        return "SensitivePropertyProviderFactory for creating AESSensitivePropertyProviders";
    }
}
