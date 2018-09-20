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

import java.util.Arrays;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.nifi.processors.standard.CryptographicHashAttribute;

/**
 * Enumeration capturing mechanisms for attribute collection used in
 * {@link CryptographicHashAttribute} processor.
 */
public enum AttributeMatchingStrategy {

    INDIVIDUAL("Individual", "Each hash is generated over a single literal attribute name"),
    LIST("List", "Each hash is generated over an ordered, delimited list of literal matches"),
    REGEX("Regex", "Each hash is generated over an ordered list of all attribute names completely matching the provided regex");

    private final String name;
    private final String description;


    AttributeMatchingStrategy(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        final ToStringBuilder builder = new ToStringBuilder(this);
        ToStringBuilder.setDefaultStyle(ToStringStyle.SHORT_PREFIX_STYLE);
        builder.append("Attribute Matching Strategy Name", name);
        builder.append("Description", description);
        return builder.toString();
    }

    public static AttributeMatchingStrategy fromName(String styleName) {
        AttributeMatchingStrategy match = Arrays.stream(AttributeMatchingStrategy.values())
                .filter(style -> styleName.equalsIgnoreCase(style.name))
                .findAny()
                .orElse(null);
        if (match == null) {
            throw new IllegalArgumentException("No attribute matching strategy matches " + styleName);
        } else {
            return match;
        }
    }
}
