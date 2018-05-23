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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class defines a {@link TlsConfiguration} instance which consists of hard-coded TLS protocols and cipher suites as determined by the Mozilla TLS Observatory as "Intermediate" for May 2018.
 *
 * @see <a href="https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29">Mozilla TLS Observatory</a>
 */
public class DefaultTlsConfiguration implements TlsConfiguration {
    // The two Poly1305 ciphers are missing because they are not yet supported in the JSSE (see http://openjdk.java.net/jeps/329)
    private static final List<String> CIPHER_SUITES = Collections.unmodifiableList(Arrays.asList(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            ));

    private static final List<String> PROTOCOLS = Collections.unmodifiableList(Arrays.asList("TLSv1.2", "TLSv1.1", "TLSv1"));

    /**
     * Returns a list of TLS cipher suites that this configuration lists. The values will be the cipher suite name as defined in the JSSE Cipher Suite Names.
     * The list is ordered by preference (descending).
     *
     * @return an ordered list of cipher suite names
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites</a>
     */
    @Override
    public List<String> getCipherSuites() {
        return CIPHER_SUITES;
    }

    /**
     * Returns an array of TLS cipher suites that this configuration lists. The values will be the cipher suite name as defined in the JSSE Cipher Suite Names.
     * The list is ordered by preference (descending). Jetty uses {@code String[]} rather than {@code List<String>}.
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites</a>
     *
     * @return an ordered array of cipher suite names
     */
    @Override
    public String[] getCipherSuitesForJetty() {
        return CIPHER_SUITES.toArray(new String[0]);
    }

    /**
     * Returns a list of TLS protocols that this configuration lists. The values will be the protocol name as defined in the JSSE {@code SSLContext} Algorithms.
     * The list is ordered by preference (descending).
     *
     * @return an ordered list of protocol names
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext</a>
     */
    @Override
    public List<String> getProtocols() {
        return PROTOCOLS;
    }

    /**
     * Returns an array of TLS protocols that this configuration lists. The values will be the protocol name as defined in the JSSE {@code SSLContext} Algorithms.
     * The list is ordered by preference (descending). Jetty uses {@code String[]} rather than {@code List<String>}.
     *
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext</a>
     *
     * @return an ordered array of protocol names
     */
    @Override
    public String[] getProtocolsForJetty() {
        return PROTOCOLS.toArray(new String[0]);
    }
}
