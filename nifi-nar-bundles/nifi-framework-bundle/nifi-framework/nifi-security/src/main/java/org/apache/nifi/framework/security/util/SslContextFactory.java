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
package org.apache.nifi.framework.security.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.util.NiFiProperties;

/**
 * A factory for creating SSL contexts using the application's security
 * properties.
 */
public final class SslContextFactory {

    public enum ClientAuth {
        WANT,
        REQUIRED,
        NONE
    }

    public enum TLSConfiguration {
        MODERN("Modern"),
        INTERMEDIATE("Intermediate"),
        OLD("Old"),
        CUSTOM("Custom");

        private String mozillaConfigName;

        TLSConfiguration(String mozillaName) {
            this.mozillaConfigName = mozillaName;
        }

        public String toString() {
            return "Mozilla TLS Configuration: " + this.mozillaConfigName;
        }

        public static String valuesAsString() {
            List<String> values = new ArrayList<>();
            for (TLSConfiguration t : values()) {
                values.add(t.mozillaConfigName);
            }
           return "[" + StringUtils.join(values, ", ") + "]";
        }
    }

    public static SSLContext createSslContext(final NiFiProperties props)
            throws SslContextCreationException {
        return createSslContext(TLSConfiguration.CUSTOM, props, false);
    }

    public static SSLContext createSslContext(final NiFiProperties props, final boolean strict)
            throws SslContextCreationException {
        return createSslContext(TLSConfiguration.CUSTOM, props, strict);
    }

    public static SSLContext createSslContext(final TLSConfiguration tlsConfiguration, final NiFiProperties props)
            throws SslContextCreationException {
        return createSslContext(tlsConfiguration, props, false);
    }

    private static boolean validateProperties(final NiFiProperties properties, final boolean strict) throws SslContextCreationException {
        final boolean hasKeystoreProperties = hasKeystoreProperties(properties);
        if (!hasKeystoreProperties) {
            if (strict) {
                throw new SslContextCreationException("SSL context cannot be created because keystore properties have not been configured.");
            } else {
                return false;
            }
        } else if (properties.getNeedClientAuth() && !hasTruststoreProperties(properties)) {
            throw new SslContextCreationException("Need client auth is set to 'true', but no truststore properties are configured.");
        }

        return true;
    }

    public static SSLContext createSslContext(final TLSConfiguration tlsConfiguration, final NiFiProperties properties, final boolean strict)
            throws SslContextCreationException {
        if (!validateProperties(properties, strict)) {
            return null;
        }

        try {
            KeyManager[] keyManagers = getKeyManagers(properties);
            TrustManager[] trustManagers = getTrustManagers(properties);

            return initSSLContext(tlsConfiguration, properties.getNeedClientAuth(), keyManagers, trustManagers);
        } catch (final KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException e) {
            throw new SslContextCreationException(e);
        }
    }

    private static KeyManager[] getKeyManagers(NiFiProperties properties) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        if (properties == null) {
            throw new IOException("NiFi properties cannot be null");
        }

        final KeyStore keyStore = KeyStore.getInstance(properties.getProperty(NiFiProperties.SECURITY_KEYSTORE_TYPE));
        try (final InputStream keyStoreStream = new FileInputStream(properties.getProperty(NiFiProperties.SECURITY_KEYSTORE))) {
            keyStore.load(keyStoreStream, properties.getProperty(NiFiProperties.SECURITY_KEYSTORE_PASSWD).toCharArray());
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        // If the key password is provided, try to use that; otherwise default to the keystore password
        if (StringUtils.isNotBlank(properties.getProperty(NiFiProperties.SECURITY_KEY_PASSWD))) {
            keyManagerFactory.init(keyStore, properties.getProperty(NiFiProperties.SECURITY_KEY_PASSWD).toCharArray());
        } else {
            keyManagerFactory.init(keyStore, properties.getProperty(NiFiProperties.SECURITY_KEYSTORE_PASSWD).toCharArray());
        }
        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] getTrustManagers(NiFiProperties properties) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        if (properties == null) {
            throw new IOException("NiFi properties cannot be null");
        }

        final KeyStore trustStore;
        if (hasTruststoreProperties(properties)) {
            trustStore = KeyStore.getInstance(properties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_TYPE));
            try (final InputStream trustStoreStream = new FileInputStream(properties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE))) {
                trustStore.load(trustStoreStream, properties.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_PASSWD).toCharArray());
            }
        } else {
            trustStore = null;
        }
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return trustManagerFactory.getTrustManagers();
    }

    private static SSLContext initSSLContext(TLSConfiguration tlsConfiguration, boolean needClientAuth, KeyManager[] keyManagers,
                                             TrustManager[] trustManagers) throws NoSuchAlgorithmException, KeyManagementException {
        // Initialize the ssl context
        // TODO: Make configurable NIFI-1478, NIFI-1480, NIFI-1688
        final SSLContext sslContext = getSslContextForTlsConfiguration(tlsConfiguration);
        sslContext.init(keyManagers,
                trustManagers, null);
        sslContext.getDefaultSSLParameters().setNeedClientAuth(needClientAuth);
        return sslContext;
    }

    private static SSLContext getSslContextForTlsConfiguration(TLSConfiguration tlsConfiguration) throws NoSuchAlgorithmException {
        if (tlsConfiguration == null) {
            throw new IllegalArgumentException("The TLS configuration must be specified. Select from " + TLSConfiguration.valuesAsString());
        }
        return SSLContext.getInstance("TLS");
    }

    private static boolean hasKeystoreProperties(final NiFiProperties props) {
        return (StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_KEYSTORE))
                && StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_KEYSTORE_PASSWD))
                && StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_KEYSTORE_TYPE)));
    }

    private static boolean hasTruststoreProperties(final NiFiProperties props) {
        return (StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_TRUSTSTORE))
                && StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_PASSWD))
                && StringUtils.isNotBlank(props.getProperty(NiFiProperties.SECURITY_TRUSTSTORE_TYPE)));
    }
}
