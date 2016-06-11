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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.nifi.util.NiFiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Change to implements after Joe's commit

/**
 * Decorator class for intermediate phase when {@link NiFiPropertiesLoader} loads the raw properties file and performs unprotection activities before returning an implementation of {@link NiFiProperties}, likely {@link StandardNiFiProperties}. This encapsulates the sensitive property access logic from external consumers of {@code NiFiProperties}.
 */
class ProtectedNiFiProperties extends StandardNiFiProperties {
    private static final Logger logger = LoggerFactory.getLogger(ProtectedNiFiProperties.class);

    private NiFiProperties internal;

    private static Map<String, SensitivePropertyProvider> localProviderCache = new HashMap<>();

    public ProtectedNiFiProperties() {
        this(new StandardNiFiProperties());
    }

    public ProtectedNiFiProperties(NiFiProperties props) {
        internal = props;
    }

    /**
     * Splits a single string containing multiple property keys into a List. Delimited by ',' or ';' and ignores leading and trailing whitespace around delimiter.
     *
     * @param multipleProperties a single String containing multiple properties, i.e. "nifi.property.1; nifi.property.2, nifi.property.3"
     * @return a List containing the split and trimmed properties
     */
    private static List<String> splitMultipleProperties(String multipleProperties) {
        if (multipleProperties == null || multipleProperties.trim().isEmpty()) {
            return new ArrayList<>(0);
        } else {
            List<String> properties = new ArrayList<>(Arrays.asList(multipleProperties.split("\\s*[,;]\\s*")));
            for (int i = 0; i < properties.size(); i++) {
                properties.set(i, properties.get(i).trim());
            }
            return properties;
        }
    }

    /**
     * Returns a list of the keys identifying "sensitive" properties. There is a default list,
     * and additional keys can be provided in the {@code nifi.sensitive.props.additional.keys} property in {@code nifi.properties}.
     *
     * @return the list of sensitive property keys
     */
    public List<String> getSensitivePropertyKeys() {
        String additionalPropertiesString = getProperty(NiFiProperties.ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
        if (additionalPropertiesString == null || additionalPropertiesString.trim().isEmpty()) {
            return NiFiProperties.DEFAULT_SENSITIVE_PROPERTIES;
        } else {
            List<String> additionalProperties = splitMultipleProperties(additionalPropertiesString);
            /* Remove this key if it was accidentally provided as a sensitive key
             * because we cannot protect it and read from it
            */
            if (additionalProperties.contains(NiFiProperties.ADDITIONAL_SENSITIVE_PROPERTIES_KEY)) {
                logger.warn("The key '{}' contains itself. This is poor practice and should be removed", NiFiProperties.ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
                additionalProperties.remove(NiFiProperties.ADDITIONAL_SENSITIVE_PROPERTIES_KEY);
            }
            additionalProperties.addAll(NiFiProperties.DEFAULT_SENSITIVE_PROPERTIES);
            return additionalProperties;
        }
    }

    /**
     * Returns true if any sensitive keys are protected.
     *
     * @return true if any key is protected; false otherwise
     */
    public boolean hasProtectedKeys() {
        List<String> sensitiveKeys = getSensitivePropertyKeys();
        for (String k : sensitiveKeys) {
            if (isPropertyProtected(k)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns a Map of the keys identifying "sensitive" properties that are currently protected and the "protection" key for each. This may or may not include all properties marked as sensitive.
     *
     * @return the Map of protected property keys and the protection identifier for each
     */
    public Map<String, String> getProtectedPropertyKeys() {
        List<String> sensitiveKeys = getSensitivePropertyKeys();

        // This is the Java 8 way, but can likely be optimized (and not sure of correctness)
        // Map<String, String> protectedProperties = sensitiveKeys.stream().filter(key ->
        // getProperty(getProtectionKey(key)) != null).collect(Collectors.toMap(Function.identity(), key ->
        // getProperty(getProtectionKey(key))));

        // Groovy
        // Map<String, String> groovyProtectedProperties = sensitiveKeys.collectEntries { key ->
        // [(key): getProperty(getProtectionKey(key))] }.findAll { k, v -> v }

        // Traditional way
        Map<String, String> traditionalProtectedProperties = new HashMap<>();
        for (String key : sensitiveKeys) {
            String protection = getProperty(getProtectionKey(key));
            if (protection != null) {
                traditionalProtectedProperties.put(key, protection);
            }
        }

        return traditionalProtectedProperties;
    }

    /**
     * Returns the unique set of all protection schemes currently in use for this instance.
     *
     * @return the set of protection schemes
     */
    public Set<String> getProtectionSchemes() {
        return new HashSet<>(getProtectedPropertyKeys().values());
    }

    /**
     * Returns a percentage of the total number of properties marked as sensitive that are currently protected.
     *
     * @return the percent of sensitive properties marked as protected
     */
    public int getPercentOfSensitivePropertiesProtected() {
        return (int) Math.round(getProtectedPropertyKeys().size() / ((double) getSensitivePropertyKeys().size()) * 100);
    }

    /**
     * Returns true if the property identified by this key is considered sensitive in this instance of {@code NiFiProperties}.
     * Some properties are sensitive by default, while others can be specified by
     * {@link NiFiProperties#ADDITIONAL_SENSITIVE_PROPERTIES_KEY}.
     *
     * @param key the key
     * @return true if it is sensitive
     * @see ProtectedNiFiProperties#getSensitivePropertyKeys()
     */
    public boolean isPropertySensitive(String key) {
        // If the explicit check for ADDITIONAL_SENSITIVE_PROPERTIES_KEY is not here, this will loop infinitely
        return key != null && !key.equals(NiFiProperties.ADDITIONAL_SENSITIVE_PROPERTIES_KEY) && getSensitivePropertyKeys().contains(key.trim());
    }

    /**
     * Returns true if the property identified by this key is considered protected in this instance of {@code NiFiProperties}.
     * The property value is protected if the key is sensitive and the sibling key of key.protected is present.
     *
     * @param key the key
     * @return true if it is currently marked as protected
     * @see ProtectedNiFiProperties#getSensitivePropertyKeys()
     */
    public boolean isPropertyProtected(String key) {
        return key != null && isPropertySensitive(key) && getProperty(getProtectionKey(key)) != null;
    }

    /**
     * Returns the sibling property key which specifies the protection scheme for this key.
     * <p>
     * Example:
     * <p>
     * nifi.sensitive.key=ABCXYZ
     * nifi.sensitive.key.protected=aes/gcm/256
     * <p>
     * nifi.sensitive.key -> nifi.sensitive.key.protected
     *
     * @param key the key identifying the sensitive property
     * @return the key identifying the protection scheme for the sensitive property
     */
    public String getProtectionKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Cannot find protection key for null key");
        }

        return key + ".protected";
    }

    /**
     * Returns the unprotected {@link NiFiProperties} instance. If none of the properties loaded are marked as protected, it will simply pass through the internal instance. If any are protected, it will drop the protection scheme keys and translate each protected value (encrypted, HSM-retrieved, etc.) into the raw value and store it under the original key.
     *
     * @return the NiFiProperties instance with all raw values
     */
    public NiFiProperties getUnprotectedProperties() {
        if (hasProtectedKeys()) {
            Map<String, String> protectedKeys = getProtectedPropertyKeys();

            logger.info("There are {} protected properties of {} sensitive properties ({}%)", protectedKeys.size(), getSensitivePropertyKeys().size(), getPercentOfSensitivePropertiesProtected());

            NiFiProperties unprotected = new StandardNiFiProperties();
            for (String key : getPropertyKeys()) {
                // Don't copy over protected or protection keys
                if (!isPropertyProtected(key) && !key.endsWith(".protected")) {
                    unprotected.setProperty(key, internal.getProperty(key));
                } else if (isPropertyProtected(key)) {
                   unprotected.setProperty(key, unprotectValue(key, internal.getProperty(key)));
                }
            }

            return unprotected;
        } else {
            logger.debug("No protected properties");
            return internal;
        }
    }

    void addSensitivePropertyProvider(SensitivePropertyProvider sensitivePropertyProvider) {
        if (sensitivePropertyProvider == null) {
            throw new IllegalArgumentException("Can not add null SensitivePropertyProvider");
        }

        getSensitivePropertyProviders().put(sensitivePropertyProvider.getIdentifierKey(), sensitivePropertyProvider);
    }

    /**
     * Returns the local provider cache (null-safe) as a Map of protection schemes -> implementations.
     *
     * @return the map
     */
    private Map<String, SensitivePropertyProvider> getSensitivePropertyProviders() {
        if (localProviderCache == null) {
            localProviderCache = new HashMap<>();
        }

        return localProviderCache;
    }

    private SensitivePropertyProvider getSensitivePropertyProvider(String protectionScheme) {
        if (isProviderAvailable(protectionScheme)) {
            return getSensitivePropertyProviders().get(protectionScheme);
        } else {
            throw new SensitivePropertyProtectionException("No provider available for " + protectionScheme);
        }
    }

    private boolean isProviderAvailable(String protectionScheme) {
        return getSensitivePropertyProviders().containsKey(protectionScheme);
    }

    /**
     * If the value is protected, unprotects it and returns it. If not, returns the original value.
     *
     * @param key            the retrieved property key
     * @param retrievedValue the retrieved property value
     * @return the unprotected value
     */
    private String unprotectValue(String key, String retrievedValue) {
        // Checks if the key is sensitive and marked as protected
        if (isPropertyProtected(key)) {
            final String protectionScheme = getProperty(getProtectionKey(key));

            // No provider registered for this scheme, so just return the value
            if (!isProviderAvailable(protectionScheme)) {
                logger.warn("No provider available for {} so passing the protected {} value back", protectionScheme, key);
                return retrievedValue;
            }

            try {
                SensitivePropertyProvider sensitivePropertyProvider = getSensitivePropertyProvider(protectionScheme);
                return sensitivePropertyProvider.unprotect(retrievedValue);
            } catch (SensitivePropertyProtectionException e) {
                throw new SensitivePropertyProtectionException("Error unprotecting value for " + key, e.getCause());
            }
        }
        return retrievedValue;
    }
}
