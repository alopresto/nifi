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

/**
 * This implementation provides a static {@link DefaultTlsConfiguration} instance which consists of hard-coded TLS protocols and cipher suites as determined by the Mozilla TLS Observatory as "Intermediate" for May 2018.
 *
 * @see <a href="https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29">Mozilla TLS Observatory</a>
 */
public class DefaultTlsConfigurationProvider implements TlsConfigurationProvider {
    /**
     * Returns a {@link DefaultTlsConfiguration}.
     *
     * @return the default configuration
     * @throws TlsConfigurationException if there is a problem retrieving the configuration
     */
    @Override
    public TlsConfiguration getConfiguration() throws TlsConfigurationException {
        return new DefaultTlsConfiguration();
    }
}
