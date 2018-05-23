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
package org.apache.nifi.web.server.tls;

import java.util.List;

/**
 * This interface defines the minimum methods that a TLS configuration must offer.
 */
public interface TlsConfiguration {
    /**
     * Returns a list of TLS cipher suites that this configuration lists. The values will be the cipher suite name as defined in the JSSE Cipher Suite Names.
     * The list is ordered by preference (descending).
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites</a>
     *
     * @return an ordered list of cipher suite names
     */
    List<String> getCipherSuites();

    /**
     * Returns an array of TLS cipher suites that this configuration lists. The values will be the cipher suite name as defined in the JSSE Cipher Suite Names.
     * The list is ordered by preference (descending). Jetty uses {@code String[]} rather than {@code List<String>}.
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites</a>
     *
     * @return an ordered array of cipher suite names
     */
    String[] getCipherSuitesForJetty();

    // TODO: Offer map of cipher suite names to hex codes for resolution with OpenSSL / RFC definitions

    /**
     * Returns a list of TLS protocols that this configuration lists. The values will be the protocol name as defined in the JSSE {@code SSLContext} Algorithms.
     * The list is ordered by preference (descending).
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext</a>
     *
     * @return an ordered list of protocol names
     */
    List<String> getProtocols();

    /**
     * Returns an array of TLS protocols that this configuration lists. The values will be the protocol name as defined in the JSSE {@code SSLContext} Algorithms.
     * The list is ordered by preference (descending). Jetty uses {@code String[]} rather than {@code List<String>}.
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext</a>
     *
     * @return an ordered array of protocol names
     */
    String[] getProtocolsForJetty();
}
