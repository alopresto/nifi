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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import org.apache.nifi.util.NiFiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NiFiPropertiesLoader {
    private static final Logger logger = LoggerFactory.getLogger(NiFiPropertiesLoader.class);

    private static final String DEFAULT_FILE_PATH = getDefaultFilePath();
    private static final String RELATIVE_PATH = "conf/nifi.properties";

    private NiFiProperties instance;
    private String keyHex;

    // Future enhancement: allow for external registration of new providers
    private static SensitivePropertyProviderFactory sensitivePropertyProviderFactory;

    public NiFiPropertiesLoader() {
    }

    /**
     * Returns an instance of the loader configured with the key.
     *
     * @param keyHex the key used to encrypt any sensitive properties
     * @return the configured loader
     */
    public static NiFiPropertiesLoader withKey(String keyHex) {
        NiFiPropertiesLoader loader = new NiFiPropertiesLoader();
        loader.setKeyHex(keyHex);
        return loader;
    }

    public void setKeyHex(String keyHex) {
        if (this.keyHex == null || this.keyHex.trim().isEmpty()) {
            this.keyHex = keyHex;
        } else {
            throw new RuntimeException("Cannot overwrite an existing key");
        }
    }

    private static String getDefaultFilePath() {
        String systemPath = System.getProperty(NiFiProperties.PROPERTIES_FILE_PATH);

        if (systemPath == null || systemPath.trim().isEmpty()) {
            logger.warn("The system variable {} is not set, so it is being set to '{}'", NiFiProperties.PROPERTIES_FILE_PATH, RELATIVE_PATH);
            System.setProperty(NiFiProperties.PROPERTIES_FILE_PATH, RELATIVE_PATH);
            systemPath = RELATIVE_PATH;
        }

        logger.info("Determined default nifi.properties path to be '{}'", systemPath);
        return systemPath;
    }

    private NiFiProperties loadDefault() {
        return load(DEFAULT_FILE_PATH);
    }

    private static String getDefaultProviderKey() {
        try {
            return "aes/gcm/" + (Cipher.getMaxAllowedKeyLength("AES") > 128 ? "256" : "128");
        } catch (NoSuchAlgorithmException e) {
            return "aes/gcm/128";
        }
    }

    private void initializeSensitivePropertyProviderFactory() {
        if (sensitivePropertyProviderFactory == null) {
            sensitivePropertyProviderFactory = new AESSensitivePropertyProviderFactory(keyHex);
        }
    }

    public NiFiProperties load(File file) {
        if (file == null || !file.exists() || !file.canRead()) {
            String path = (file == null ? "missing file" : file.getAbsolutePath());
            logger.error("Cannot read from '{}' -- file is missing or not readable", path);
            throw new IllegalArgumentException("NiFi properties file missing or unreadable");
        }

        ProtectedNiFiProperties protectedNiFiProperties = new ProtectedNiFiProperties();

        InputStream inStream = null;
        try {
            inStream = new BufferedInputStream(new FileInputStream(file));
            protectedNiFiProperties.load(inStream);
            logger.info("Loaded {} properties from {}", instance.size(), file.getAbsolutePath());

            if (protectedNiFiProperties.hasProtectedKeys()) {
                initializeSensitivePropertyProviderFactory();
                protectedNiFiProperties.addSensitivePropertyProvider(sensitivePropertyProviderFactory.getProvider());
            }

            return protectedNiFiProperties.getUnprotectedProperties();
        } catch (final Exception ex) {
            logger.error("Cannot load properties file due to " + ex.getLocalizedMessage());
            throw new RuntimeException("Cannot load properties file due to "
                    + ex.getLocalizedMessage(), ex);
        } finally {
            if (null != inStream) {
                try {
                    inStream.close();
                } catch (final Exception ex) {
                    /**
                     * do nothing *
                     */
                }
            }
        }
    }

    public NiFiProperties load(String path) {
        if (path != null && !path.trim().isEmpty()) {
            return load(new File(path));
        } else {
            return loadDefault();
        }
    }

    public NiFiProperties get() {
        if (instance == null) {
            instance = loadDefault();
        }

        return instance;
    }
}
