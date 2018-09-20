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

package org.apache.nifi.processors.standard;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.nifi.annotation.behavior.DynamicProperty;
import org.apache.nifi.annotation.behavior.EventDriven;
import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.SideEffectFree;
import org.apache.nifi.annotation.behavior.SupportsBatching;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.security.util.attributes.AttributeMatchingService;
import org.apache.nifi.security.util.attributes.AttributeMatchingStrategy;
import org.apache.nifi.security.util.crypto.HashAlgorithm;
import org.apache.nifi.security.util.crypto.HashService;
import org.apache.nifi.util.StringUtils;

@EventDriven
@SideEffectFree
@SupportsBatching
@Tags({"attributes", "hash", "md5", "sha", "keccak", "blake2", "cryptography"})
@InputRequirement(InputRequirement.Requirement.INPUT_REQUIRED)
@CapabilityDescription("Calculates a hash value for each of the specified attributes using the given algorithm and writes it to an output attribute. Please refer to https://csrc.nist.gov/Projects/Hash-Functions/NIST-Policy-on-Hash-Functions for help to decide which algorithm to use. ")
@WritesAttribute(attribute = "<Specified Attribute Name per Dynamic Property>", description = "This Processor adds an attribute whose value is the result of "
        + "hashing the specified attribute(s). The name of each dynamic property is the name of the new attribute, " +
        "and the value of the property determines which attribute(s) are collected and hashed, depending on the Attribute Matching Strategy. "
        + "Attributes are case-sensitive, so 'MY_ATTR' will not be matched by 'my_attr', 'SOME_ATTR, My_Attr', or '.*_attr'. ")
@DynamicProperty(name = "A flowfile attribute key for attribute inspection", value = "Attribute Name",
        description = "The property name defines the new attribute which will be added to the resulting flowfile. "
                + "The property value defines the attribute(s) to look for and hash in the incoming flowfile. "
                + "Attribute names must be unique.")
public class CryptographicHashAttribute extends AbstractProcessor {
    public enum PartialAttributePolicy {
        ALLOW,
        PROHIBIT
    }

    // TODO: Refactor to remove enum and rename to "fail if missing some"
    private static final AllowableValue ALLOW_PARTIAL_ATTRIBUTES_VALUE = new AllowableValue(PartialAttributePolicy.ALLOW.name(),
            "Allow missing attributes",
            "Do not route to failure if there are attributes configured for hashing that are not present in the flowfile");

    private static final AllowableValue FAIL_PARTIAL_ATTRIBUTES_VALUE = new AllowableValue(PartialAttributePolicy.PROHIBIT.name(),
            "Fail if missing attributes",
            "Route to failure if there are attributes configured for hashing that are not present in the flowfile");

    static final PropertyDescriptor CHARACTER_SET = new PropertyDescriptor.Builder()
            .name("character_set")
            .displayName("Character Set")
            .description("The Character Set used to decode the attribute being hashed -- this applies to the incoming data encoding, not the resulting hash encoding. ")
            .required(true)
            .allowableValues(HashService.buildCharacterSetAllowableValues())
            .addValidator(StandardValidators.CHARACTER_SET_VALIDATOR)
            .defaultValue("UTF-8")
            .build();

    static final PropertyDescriptor FAIL_WHEN_EMPTY = new PropertyDescriptor.Builder()
            .name("fail_when_empty")
            .displayName("Fail when no attributes present")
            .description("Route to failure when none of the attributes that are configured for hashing are found. " +
                    "If set to false, then flow files that do not contain any of the attributes that are configured for hashing will just pass through to success.")
            .allowableValues("true", "false")
            .required(true)
            .addValidator(StandardValidators.BOOLEAN_VALIDATOR)
            .defaultValue("true")
            .build();

    static final PropertyDescriptor ATTRIBUTE_MATCHING_STRATEGY = new PropertyDescriptor.Builder()
            .name("attribute_matching_strategy")
            .displayName("Attribute Matching Strategy")
            .description("The attribute matching strategy to use. Attribute(s) matching the dynamic properties given this strategy will be combined and hashed.")
            .required(true)
            .allowableValues(buildAttributeMatchingStrategyAllowableValues())
            .defaultValue(AttributeMatchingStrategy.INDIVIDUAL.getName())
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    static final PropertyDescriptor HASH_ALGORITHM = new PropertyDescriptor.Builder()
            .name("hash_algorithm")
            .displayName("Hash Algorithm")
            .description("The cryptographic hash algorithm to use. Note that not all of the algorithms available are recommended for use (some are provided for legacy use). " +
                    "There are many things to consider when picking an algorithm; it is recommended to use the most secure algorithm possible.")
            .required(true)
            .allowableValues(HashService.buildHashAlgorithmAllowableValues())
            .defaultValue(HashAlgorithm.SHA256.getName())
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    static final PropertyDescriptor PARTIAL_ATTR_ROUTE_POLICY = new PropertyDescriptor.Builder()
            .name("missing_attr_policy")
            .displayName("Missing attribute policy")
            .description("Policy for how the processor handles attributes that are configured for hashing but are not found in the flowfile.")
            .required(true)
            .allowableValues(ALLOW_PARTIAL_ATTRIBUTES_VALUE, FAIL_PARTIAL_ATTRIBUTES_VALUE)
            .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
            .defaultValue(ALLOW_PARTIAL_ATTRIBUTES_VALUE.getValue())
            .build();

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("Used for flowfiles that have a hash value added")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("Used for flowfiles that are missing required attributes")
            .build();
    private final static Set<Relationship> relationships;

    private final static List<PropertyDescriptor> properties;

    private final AtomicReference<Map<String, String>> attributeToGenerateNameMapRef = new AtomicReference<>(Collections.emptyMap());

    static {
        final Set<Relationship> _relationships = new HashSet<>();
        _relationships.add(REL_FAILURE);
        _relationships.add(REL_SUCCESS);
        relationships = Collections.unmodifiableSet(_relationships);

        final List<PropertyDescriptor> _properties = new ArrayList<>();
        _properties.add(CHARACTER_SET);
        _properties.add(FAIL_WHEN_EMPTY);
        _properties.add(HASH_ALGORITHM);
        _properties.add(ATTRIBUTE_MATCHING_STRATEGY);
        _properties.add(PARTIAL_ATTR_ROUTE_POLICY);
        properties = Collections.unmodifiableList(_properties);
    }

    /**
     * Returns an array of {@link AllowableValue} elements for each {@link AttributeMatchingStrategy}.
     *
     * @return an ordered {@code AllowableValue[]} containing the values
     */
    private static AllowableValue[] buildAttributeMatchingStrategyAllowableValues() {
        final AttributeMatchingStrategy[] attributeMatchingStrategies = AttributeMatchingStrategy.values();
        return Arrays.stream(attributeMatchingStrategies).map(ams ->
                new AllowableValue(ams.getName(), ams.getName(), ams.getDescription()))
                .toArray(AllowableValue[]::new);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return relationships;
    }

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return properties;
    }

    @Override
    protected PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyDescriptorName) {
        return new PropertyDescriptor.Builder()
                .name(propertyDescriptorName)
                .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
                .build();
    }

    @Override
    public void onPropertyModified(final PropertyDescriptor descriptor, final String oldValue, final String newValue) {
        if (!descriptor.isDynamic()) {
            return;
        }

        final Map<String, String> attributeToGeneratedNameMap = new HashMap<>(attributeToGenerateNameMapRef.get());
        if (newValue == null) {
            attributeToGeneratedNameMap.remove(descriptor.getName());
        } else {
            attributeToGeneratedNameMap.put(descriptor.getName(), newValue);
        }

        attributeToGenerateNameMapRef.set(Collections.unmodifiableMap(attributeToGeneratedNameMap));
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }
        final Charset charset = Charset.forName(context.getProperty(CHARACTER_SET).getValue());
        final Map<String, String> attributeToGeneratedNameMap = attributeToGenerateNameMapRef.get();
        final ComponentLog logger = getLogger();

        final AttributeMatchingStrategy ams = AttributeMatchingStrategy.fromName(context.getProperty(ATTRIBUTE_MATCHING_STRATEGY).getValue());
        logger.info("Using attribute matching strategy " + ams.getName());

        // Get a map of the attributes to be hashed
        final Map<String, List<String>> attributeNamesToHash = getAttributeNamesToHash(flowFile, ams, attributeToGeneratedNameMap);

        // Flatten, deduplicate, and sort the attribute names required for all hashing operations
        List<String> attributesRequiredForHashing = flattenAndUniqueList(attributeNamesToHash.values());
        logger.info("Parsed {} attributes to be hashed: [{}]", new Object[]{attributesRequiredForHashing.size(), StringUtils.join(attributesRequiredForHashing, ", ")});

        // If flowfile is missing required attributes, route to failure
        boolean failWhenEmpty = context.getProperty(FAIL_WHEN_EMPTY).asBoolean();
        boolean allowPartialAttributes = PartialAttributePolicy.ALLOW.equals(PartialAttributePolicy.valueOf(context.getProperty(PARTIAL_ATTR_ROUTE_POLICY).getValue()));
        if (shouldRouteToFailureIfNecessaryAttributesMissing(attributesRequiredForHashing, flowFile, failWhenEmpty, allowPartialAttributes)) {
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        // Determine the algorithm to use
        final String algorithmName = context.getProperty(HASH_ALGORITHM).getValue();
        logger.debug("Using algorithm {}", new Object[]{algorithmName});
        HashAlgorithm algorithm = HashAlgorithm.fromName(algorithmName);

        // Iterate over the attribute(s) to hash and populate them in the new attribute
        for (final Map.Entry<String, List<String>> entry : attributeNamesToHash.entrySet()) {
            final String destinationAttributeName = entry.getKey();
            final List<String> attributesToHash = entry.getValue();
            logger.debug("Generating {} hash for attribute {} over [{}]", new Object[]{algorithmName, destinationAttributeName, StringUtils.join(attributesToHash, ", ")});
            try {
                String valueToHash = constructValueToHash(flowFile, attributesToHash);
                String hashValue = hashValue(algorithm, valueToHash, charset);
                session.putAttribute(flowFile, destinationAttributeName, hashValue);
            } catch (IllegalArgumentException e) {
                logger.warn("Cannot hash a null value for {} attribute {}; ignoring", new Object[]{flowFile, destinationAttributeName});
            }
        }
        session.getProvenanceReporter().modifyAttributes(flowFile);
        session.transfer(flowFile, REL_SUCCESS);
    }

    /**
     * Returns a {@link String} containing the value to hash. This method filters attributes which contain {@code null} values but allows attributes which contain an empty string.
     *
     * @param flowFile       the flowfile
     * @param attributeNames the ordered list of attribute names to enumerate
     * @return the string to hash
     * @throws IllegalArgumentException if all values are {@code null} as there will be no value to hash
     */
    private String constructValueToHash(FlowFile flowFile, List<String> attributeNames) {
        final List<String> attributeValues = attributeNames.stream()
                .filter(attr -> flowFile.getAttribute(attr) != null)
                .map(flowFile::getAttribute)
                .collect(Collectors.toList());
        if (attributeValues.isEmpty()) {
            throw new IllegalArgumentException("All attribute values were null");
        } else {
            return StringUtils.join(attributeValues, "");
        }
    }

    /**
     * Returns true if the flowfile should be routed to failure. This method handles printing log messages.
     *
     * @param expectedAttributes     the list of expected attribute names
     * @param flowFile               the flowfile
     * @param failWhenEmpty          true if the flowfile should fail if missing all attributes
     * @param allowPartialAttributes false if the flowfile should fail if missing any attributes
     * @return true if the flowfile should fail
     */
    private boolean shouldRouteToFailureIfNecessaryAttributesMissing(List<String> expectedAttributes, FlowFile flowFile, boolean failWhenEmpty, boolean allowPartialAttributes) {
        ComponentLog logger = getLogger();
        // If no attributes are going to be hashed, return immediately
        if (expectedAttributes.isEmpty()) {
            return false;
        }

        // Determine which (if any) attributes are missing
        List<String> missingAttributes = expectedAttributes.parallelStream()
                .filter(attr -> flowFile.getAttribute(attr) == null)
                .collect(Collectors.toList());
        if (logger.isDebugEnabled()) {
            logger.debug("Of {} attributes to be hashed, {} are missing: [{}]", new Object[]{expectedAttributes.size(), missingAttributes.size(), StringUtils.join(missingAttributes, ", ")});
        }

        // All attributes are present
        if (missingAttributes.isEmpty()) {
            return false;
        }

        // If all are missing, check to see if this should fail
        if (missingAttributes.size() == expectedAttributes.size()) {
            return shouldFailWhenEmpty(flowFile, failWhenEmpty, missingAttributes);
        } else {
            // Only some are missing
            return shouldFailWhenSomeAttributesMissing(expectedAttributes, flowFile, allowPartialAttributes, missingAttributes);
        }
    }

    /**
     * Returns true if the flowfile should be routed to 'failure' given the missing and required attributes depending on the {@code allowPartialAttributes} setting.
     *
     * @param expectedAttributes     the list of expected attributes
     * @param flowFile               the flowfile (for logging purposes)
     * @param allowPartialAttributes true if a flowfile with some missing attributes is allowed
     * @param missingAttributes      the list of missing attributes
     * @return true if the flowfile should be routed to failure
     */
    private boolean shouldFailWhenSomeAttributesMissing(List<String> expectedAttributes, FlowFile flowFile, boolean allowPartialAttributes, List<String> missingAttributes) {
        ComponentLog logger = getLogger();
        if (allowPartialAttributes) {
            if (logger.isDebugEnabled()) {
                logger.debug("Not routing {} to 'failure' even though {} of {} expected attributes are missing because missing attributes are allowed: [{}]",
                        new Object[]{flowFile, missingAttributes.size(), expectedAttributes.size(), StringUtils.join(missingAttributes, ", ")});
            }
        } else {
            logger.info("Routing {} to 'failure' because {} of {} expected attributes are missing: [{}]",
                    new Object[]{flowFile, missingAttributes.size(), expectedAttributes.size(), StringUtils.join(missingAttributes, ", ")});
            return true;
        }
        return false;
    }

    /**
     * Returns true if the flowfile should be routed to 'failure' given the missing and required attributes depending on the {@code failWhenEmpty} setting.
     *
     * @param flowFile          the flowfile (for logging purposes)
     * @param failWhenEmpty     true if a flowfile missing all expected attributes should fail
     * @param missingAttributes the list of missing attributes
     * @return true if the flowfile should be routed to failure
     */
    private boolean shouldFailWhenEmpty(FlowFile flowFile, boolean failWhenEmpty, List<String> missingAttributes) {
        ComponentLog logger = getLogger();
        if (failWhenEmpty) {
            logger.info("Routing {} to 'failure' because all expected attributes are missing: [{}]", new Object[]{flowFile, StringUtils.join(missingAttributes, ", ")});
            return true;
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Not routing {} to 'failure' even though all expected attributes are missing because failWhenEmpty is false: [{}]",
                        new Object[]{flowFile, StringUtils.join(missingAttributes, ", ")});
            }
        }
        return false;
    }

    /**
     * Returns a single {@code List<String>} containing the unique and sorted elements in all of the provided nested lists.
     *
     * @param values a nested {@code List<List<String>>} containing the individual attribute names
     * @return the comprehensive list of attributes
     */
    private List<String> flattenAndUniqueList(Collection<List<String>> values) {
        return values.stream().flatMap(List::stream).distinct().sorted().collect(Collectors.toList());
    }

    /**
     * Returns a {@link Map} of destination attribute names -> [attribute names to hash]. The {@link AttributeMatchingStrategy} determines how each list is generated.
     *
     * @param flowFile           the incoming flowfile
     * @param ams                the AttributeMatchingStrategy to use
     * @param dynamicPropertyMap a map of destination attribute names -> literal or regex pattern to include
     * @return a Map of attribute names to an ordered List of attribute names to be hashed and stored in that attribute
     */
    private Map<String, List<String>> getAttributeNamesToHash(final FlowFile flowFile, final AttributeMatchingStrategy ams, final Map<String, String> dynamicPropertyMap) {
        final ComponentLog logger = getLogger();
        Map<String, List<String>> destinationAttributes = new HashMap<>();
        for (final Map.Entry<String, String> e : dynamicPropertyMap.entrySet()) {
            final String destinationAttributeName = e.getKey();
            final List<String> attributesToHash = AttributeMatchingService.getAttributes(e.getValue(), ams, flowFile);
            if (logger.isDebugEnabled()) {
                logger.debug("Parsed '{}' to consist of hash of {} attributes: [{}]",
                        new Object[]{destinationAttributeName, attributesToHash.size(), StringUtils.join(attributesToHash, ", ")});
            }
            destinationAttributes.put(destinationAttributeName, attributesToHash);
        }

        logger.info("Parsed {} destination attributes: [{}]", new Object[]{destinationAttributes.size(), StringUtils.join(destinationAttributes.keySet(), ", ")});

        return destinationAttributes;
    }

    /**
     * Returns the calculated hash value given the input, algorithm, and charset. Will return an empty string {@code ""} on {@code null} input.
     *
     * @param algorithm the hash algorithm
     * @param value     the input (can be null)
     * @param charset   the charset for decoding the input
     * @return the hash
     */
    private String hashValue(HashAlgorithm algorithm, String value, Charset charset) {
        if (value == null) {
            getLogger().warn("Tried to calculate {} hash of null value; returning empty string", new Object[]{algorithm.getName()});
            return "";
        }
        return HashService.hashValue(algorithm, value, charset);
    }
}

