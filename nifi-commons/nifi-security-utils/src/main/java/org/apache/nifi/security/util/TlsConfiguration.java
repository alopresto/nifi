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
package org.apache.nifi.security.util;

import java.io.File;
import java.net.MalformedURLException;
import java.util.Objects;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class serves as an immutable domain object (acting as an internal DTO) for the various keystore and truststore configuration settings necessary for building {@link javax.net.ssl.SSLContext}s.
 */
public class TlsConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(TlsConfiguration.class);

    private final String keystorePath;
    private final String keystorePassword;
    private final String keyPassword;
    private final KeystoreType keystoreType;

    private final String truststorePath;
    private final String truststorePassword;
    private final KeystoreType truststoreType;

    /**
     * Default constructor present for testing and completeness.
     */
    public TlsConfiguration() {
        this(null, null, null, null, null, null, null);
    }

    /**
     * Instantiates a container object with the given configuration values.
     *
     * @param keystorePath       the keystore path
     * @param keystorePassword   the keystore password
     * @param keystoreType       the keystore type
     * @param truststorePath     the truststore path
     * @param truststorePassword the truststore password
     * @param truststoreType     the truststore type
     */
    public TlsConfiguration(String keystorePath, String keystorePassword, KeystoreType keystoreType, String truststorePath, String truststorePassword, KeystoreType truststoreType) {
        this(keystorePath, keystorePassword, keystorePassword, keystoreType, truststorePath, truststorePassword, truststoreType);
    }

    /**
     * Instantiates a container object with the given configuration values.
     *
     * @param keystorePath       the keystore path
     * @param keystorePassword   the keystore password
     * @param keyPassword        the (optional) key password -- if {@code null}, the keystore password is assumed the same for the individual key
     * @param keystoreType       the keystore type
     * @param truststorePath     the truststore path
     * @param truststorePassword the truststore password
     * @param truststoreType     the truststore type
     */
    public TlsConfiguration(String keystorePath, String keystorePassword, String keyPassword, KeystoreType keystoreType, String truststorePath, String truststorePassword, KeystoreType truststoreType) {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyPassword = keyPassword;
        this.keystoreType = keystoreType;
        this.truststorePath = truststorePath;
        this.truststorePassword = truststorePassword;
        this.truststoreType = truststoreType;
    }

    /**
     * Instantiates a container object with a deep copy of the given configuration values.
     *
     * @param other the configuration to copy
     */
    public TlsConfiguration(TlsConfiguration other) {
        this.keystorePath = other.keystorePath;
        this.keystorePassword = other.keystorePassword;
        this.keyPassword = other.keyPassword;
        this.keystoreType = other.keystoreType;
        this.truststorePath = other.truststorePath;
        this.truststorePassword = other.truststorePassword;
        this.truststoreType = other.truststoreType;
    }

    // Static factory method from NiFiProperties

    /**
     * Returns a {@link TlsConfiguration} instantiated from the relevant {@link NiFiProperties} properties.
     *
     * @param niFiProperties the NiFi properties
     * @return a populated TlsConfiguration container object
     */
    public static TlsConfiguration fromNiFiProperties(NiFiProperties niFiProperties) {
        String keystorePath = niFiProperties.getProperty(NiFiProperties.SECURITY_KEYSTORE);
        String keystorePassword = niFiProperties.getProperty(NiFiProperties.SECURITY_KEYSTORE_PASSWD);
        String keyPassword = niFiProperties.getProperty(NiFiProperties.SECURITY_KEY_PASSWD);
        String keystoreType = niFiProperties.getProperty(NiFiProperties.SECURITY_KEYSTORE_TYPE);
        String truststorePath = niFiProperties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE);
        String truststorePassword = niFiProperties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_PASSWD);
        String truststoreType = niFiProperties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_TYPE);

        if (logger.isDebugEnabled()) {
            String logKeystorePassword = StringUtils.isNotBlank(keystorePassword) ? "********" : "null";
            String logKeyPassword = StringUtils.isNotBlank(keyPassword) ? "********" : "null";
            String logTruststorePassword = StringUtils.isNotBlank(truststorePassword) ? "********" : "null";
            logger.debug("Instantiating TlsConfiguration from NiFi properties: {}, {}, {}, {}, {}, {}, {}", keystorePath, logKeystorePassword, logKeyPassword, keystoreType, truststorePath, logTruststorePassword, truststoreType);
        }

        return new TlsConfiguration(keystorePath, keystorePassword, keyPassword, KeystoreType.valueOf(keystoreType), truststorePath, truststorePassword, KeystoreType.valueOf(truststoreType));
    }

    // Getters & setters

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    /**
     * Returns the "working" key password -- if the key password is populated, it is returned; otherwise the {@link #getKeystorePassword()} is returned.
     *
     * @return the key or keystore password actually populated
     */
    public String getFunctionalKeyPassword() {
        return keyPassword != null && !keyPassword.isEmpty() ? keyPassword : keystorePassword;
    }

    public KeystoreType getKeystoreType() {
        return keystoreType;
    }

    public String getTruststorePath() {
        return truststorePath;
    }

    public String getTruststorePassword() {
        return truststorePassword;
    }

    public KeystoreType getTruststoreType() {
        return truststoreType;
    }

    // Boolean validators for keystore & truststore

    /**
     * Returns {@code true} if the necessary properties are populated to instantiate a <strong>keystore</strong>. This does <em>not</em> validate the values (see {@link #isKeystoreValid()}).
     *
     * @return true if the path, password, and type are present
     */
    public boolean isKeystorePopulated() {
        return isStorePopulated(keystorePath, keystorePassword, keystoreType, "keystore");
    }

    /**
     * Returns {@code true} if the necessary properties are populated and the keystore can be successfully instantiated (i.e. the path is valid and the password(s) are correct).
     *
     * @return true if the keystore properties are valid
     */
    public boolean isKeystoreValid() {
        boolean simpleCheck = isStoreValid(keystorePath, getFunctionalKeyPassword(), keystoreType, "keystore");
        if (simpleCheck) {
            return true;
        } else {
            try {
                return isKeystorePopulated() && KeyStoreUtils.isKeyPasswordCorrect(new File(keystorePath).toURI().toURL(), keystoreType, keystorePassword.toCharArray(), getFunctionalKeyPassword().toCharArray());
            } catch (MalformedURLException e) {
                logger.error("Encountered an error validating the keystore: " + e.getLocalizedMessage());
                return false;
            }
        }
    }

    /**
     * Returns {@code true} if the necessary properties are populated to instantiate a <strong>truststore</strong>. This does <em>not</em> validate the values (see {@link #isTruststoreValid()}).
     *
     * @return true if the path, password, and type are present
     */
    public boolean isTruststorePopulated() {
        return isStorePopulated(truststorePath, truststorePassword, truststoreType, "truststore");
    }

    /**
     * Returns {@code true} if the necessary properties are populated and the truststore can be successfully instantiated (i.e. the path is valid and the password is correct).
     *
     * @return true if the truststore properties are valid
     */
    public boolean isTruststoreValid() {
        return isStoreValid(truststorePath, truststorePassword, truststoreType, "truststore");
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("keystorePath", keystorePath)
                .append("keystorePassword", StringUtils.isNotBlank(keystorePassword) ? "********" : "null")
                .append("keyPassword", StringUtils.isNotBlank(keyPassword) ? "********" : "null")
                .append("keystoreType", keystoreType)
                .append("truststorePath", truststorePath)
                .append("truststorePassword", StringUtils.isNotBlank(truststorePassword) ? "********" : "null")
                .append("truststoreType", truststoreType)
                .toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TlsConfiguration that = (TlsConfiguration) o;
        return Objects.equals(keystorePath, that.keystorePath)
                && Objects.equals(keystorePassword, that.keystorePassword)
                && Objects.equals(keyPassword, that.keyPassword)
                && keystoreType == that.keystoreType
                && Objects.equals(truststorePath, that.truststorePath)
                && Objects.equals(truststorePassword, that.truststorePassword)
                && truststoreType == that.truststoreType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(keystorePath, keystorePassword, keyPassword, keystoreType, truststorePath, truststorePassword, truststoreType);
    }

    private static boolean isStorePopulated(String path, String password, KeystoreType type, String label) {
        boolean isPopulated = StringUtils.isNotBlank(path)
                && StringUtils.isNotBlank(password)
                && type != null;
        if (logger.isDebugEnabled()) {
            logger.debug("TLS config {} is {}: {}, ********, {}", label, isPopulated ? "populated" : "not populated", path, type);
        }
        return isPopulated;
    }

    private static boolean isStoreValid(String path, String password, KeystoreType type, String label) {
        try {
            return isStorePopulated(path, password, type, label) && KeyStoreUtils.isStoreValid(new File(path).toURI().toURL(), type, password.toCharArray());
        } catch (MalformedURLException e) {
            logger.error("Encountered an error validating the " + label + ": " + e.getLocalizedMessage());
            return false;
        }
    }
}
