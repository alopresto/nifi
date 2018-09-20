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
package org.apache.nifi.security.util.attributes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.flowfile.FlowFile;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides a generic service for extracting attributes from a flowfile.
 */
public class AttributeMatchingService {
    private static final Logger logger = LoggerFactory.getLogger(AttributeMatchingService.class);
    private static final String DELIMITER = ",";
    private static final List<String> KNOWN_MATCH_ALL_PATTERNS = Arrays.asList(".*", "(.*)", "[.]*");


    /**
     * Returns the {@link List} of attributes to hash for a given {@link AttributeMatchingStrategy}.
     *
     * @param attributeString the literal, list, or regex pattern to parse
     * @param ams             the AttributeMatchingStrategy to use
     * @param flowFile        the flowfile containing the attributes (only required for {@code AttributeMatchingStrategy.REGEX})
     * @return the ordered list of attributes to hash
     */
    public static List<String> getAttributes(String attributeString, AttributeMatchingStrategy ams, FlowFile flowFile) {
        if (attributeString == null || StringUtil.isBlank(attributeString)) {
            logger.error("The attribute string cannot be empty");
            return Collections.emptyList();
        }

        switch (ams) {
            case INDIVIDUAL:
                return getIndividualAttribute(attributeString);
            case LIST:
                // TODO: Make configurable from processor
                return getListAttributes(attributeString, DELIMITER);
            case REGEX:
                return getRegexAttributes(attributeString, flowFile);
            default:
                logger.error("Unknown attribute matching strategy {}; returning empty list", ams.getName());
                return Collections.emptyList();
        }
    }

    /**
     * Returns a {@code List<String>} containing the single attribute specified by literal name in the input.
     *
     * @param attributeString contains the attribute name to be parsed. Leading and trailing whitespace is allowed and will be trimmed
     * @return the attribute name in a List
     */
    static List<String> getIndividualAttribute(String attributeString) {
        String trimmedAttribute = attributeString.trim();
        List<String> attributes = trimmedAttribute.equalsIgnoreCase("")
                ? Collections.emptyList()
                : Collections.singletonList(trimmedAttribute);
        printMetrics(attributeString, attributes, AttributeMatchingStrategy.INDIVIDUAL);

        return attributes;
    }

    /**
     * Returns an ordered {@code List<String>} containing the attribute names specified by the
     * input. The names are parsed in order with the given delimiter and trimmed. If the delimiter
     * is not found, the entire input is returned as the single element in the list.
     * <p>
     * Ex:
     * <pre>
     * {@code
     * "a/b/c" + '/' -> ["a", "b", "c"] (3)
     * "a, c, b" + ',' -> ["a", "c", "b"] (3)
     * "a, b, c" + '/' -> ["a, b, c"] (1)
     * }
     * </pre>
     *
     * @param attributeString contains the attribute name(s) to be parsed. Leading and trailing whitespace is allowed and will be trimmed
     * @param delimiter       the delimiter to split on
     * @return the attribute names in a List
     */
    static List<String> getListAttributes(String attributeString, String delimiter) {
        logger.debug("Using delimiter " + delimiter);
        List<String> attributes = Arrays.stream(StringUtils.split(attributeString, delimiter))
                .map(String::trim).collect(Collectors.toList());
        printMetrics(attributeString, attributes, AttributeMatchingStrategy.LIST);

        return attributes;
    }

    /**
     * Returns an ordered {@code List<String>} containing the attribute names specified by the input. The names are
     * lexicographically ordered regardless of which matched the pattern first. Only complete matches with the regex
     * are included.
     * <p>
     * If the "match all" pattern ({@code .*}) is used, all attributes are returned, bypassing actual evaluation of
     * the pattern against each attribute name for performance reasons.
     * <p>
     * Ex:
     * <p>
     * Flowfile attributes: {@code "my_attr", "my_attr_2", "earlier_attribute"}
     *
     * <pre>
     * {@code
     * "my_attr" -> ["my_attr"] (1)
     * "my_attr.*" -> ["my_attr", "my_attr_2"] (2)
     * ".*_attr.*" -> ["earlier_attribute", "my_attr", "my_attr_2"] (3)
     * }
     * </pre>
     *
     * @param attributeString contains the pattern used to match the attribute names
     * @param flowFile        contains the attribute map
     * @return the attribute names in a List
     */
    static List<String> getRegexAttributes(String attributeString, FlowFile flowFile) {
        // Create a list of the attribute names and sort them
        List<String> flowfileAttributes = new ArrayList<>(flowFile.getAttributes().keySet());
        Collections.sort(flowfileAttributes);

        // If the pattern is /.*/, save time on filtering by returning all attributes
        if (isMatchAllPattern(attributeString)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Pattern matched all attributes; returning {} attributes: [{}]", flowfileAttributes.size(), StringUtils.join(flowfileAttributes, ", "));
            }
            return flowfileAttributes;
        }

        List<String> attributes = flowfileAttributes.stream()
                .filter(attr -> attr.matches(attributeString)).collect(Collectors.toList());
        printMetrics(attributeString, attributes, AttributeMatchingStrategy.REGEX);

        return attributes;
    }

    /**
     * Returns true if this pattern is the global "match all" pattern. This <strong>does not</strong> evaluate <em>equality</em> to "match all" -- there are possible patterns which can match all
     * inputs that this method will return false for. Rather, the method is useful when determining
     * if the actual evaluation should be bypassed because the user wants to simply match all
     * attributes.
     * <p>
     * Matches: {@code [".*", "(.*)", "[.]*"]}
     *
     * @param pattern the pattern to check
     * @return true if the pattern is intended to match all inputs
     */
    static boolean isMatchAllPattern(String pattern) {
        return KNOWN_MATCH_ALL_PATTERNS.contains(pattern.trim());
    }

    private static void printMetrics(String attributeString, List<String> attributes, AttributeMatchingStrategy ams) {
        if (logger.isDebugEnabled()) {
            logger.debug("Parsed '{}' using {} to {} attributes: [{}]",
                    attributeString,
                    ams.getName(),
                    attributes.size(),
                    StringUtils.join(attributes, ", "));
        }
    }
}
