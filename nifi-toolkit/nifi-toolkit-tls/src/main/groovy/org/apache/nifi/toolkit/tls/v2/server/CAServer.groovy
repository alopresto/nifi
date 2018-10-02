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

package org.apache.nifi.toolkit.tls.v2.server


import org.apache.nifi.toolkit.tls.v2.ca.CAService
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.server.Handler
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.HttpConnectionFactory
import org.eclipse.jetty.server.SecureRequestCustomizer
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyPair
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

class CAServer {
    private static final Logger logger = LoggerFactory.getLogger(CAServer.class)

    static final String DEFAULT_KEYSTORE_PATH = "./conf/keystore.jks"
    static final String DEFAULT_ALIAS = "nifi-key"
    static final String DEFAULT_DN = "CN=nifi-ca, OU=NiFi"
    static final int DEFAULT_PORT = 1443

    private Server server
    private KeyStore keystore

    CAServer(int port = DEFAULT_PORT, String keystorePath = DEFAULT_KEYSTORE_PATH, String keystorePassword, String token, String alias = DEFAULT_ALIAS, String dn = DEFAULT_DN) {
        // TODO: Handle different key password
        // Generate or locate keystore
        KeyStore keystore = generateOrLocateKeystore(keystorePath, keystorePassword, alias, dn)
        // Create CAService with CA cert and token
        CAService caService = createCAService(keystore, keystorePassword, token, alias)
        // Create CAHandler
        CAHandler caHandler = new CAHandler(caService)
        // Create server
        this.server = createServer(caHandler, port, keystore, keystorePassword)
    }

    // TODO: Add constructor for external CA

    // TODO: Add KeyStore generator for external CA?
    // TODO: Or inject different CAService impls based on signing material?

    static CAService createCAService(KeyStore keystore, String keyPassword, String token, String alias) {
        PrivateKey privateKey = keystore.getKey(alias, keyPassword.chars) as PrivateKey
        X509Certificate caCert = keystore.getCertificate(alias) as X509Certificate
        PublicKey publicKey = caCert.publicKey
        new CAService(token, publicKey, privateKey, caCert)
    }

    // TODO: Refactor into components
    // TODO: Make static
    KeyStore generateOrLocateKeystore(String keystorePath, String keystorePassword, String alias, String dn) {
        KeyStore keyStore

        try {
            // Try loading from file
            if (keystorePath) {
                keystore = loadKeystoreContainingAlias(keystorePath, keystorePassword, alias)
            } else {
                keystore = generateCAKeystore(dn, alias, keystorePassword)
            }
        } catch (KeyStoreException kse) {
            // Keystore loads but does not contain alias
            logger.warn("Because the expected alias could not be loaded, generate a new CA key and cert and inject it in this keystore")
            keystore = addCAToKeystore(dn, alias, keystorePassword, keystore)
            // Write the modified keystore to the file
            writeKeystore(keystore, keystorePassword, keystorePath)
        } catch (IOException ioe) {
            // No keystore at all
            logger.warn("Failed to load the keystore, generate a new keystore containing a CA key and cert")
            keystore = generateCAKeystore(dn, alias, keystorePassword)
            writeKeystore(keystore, keystorePassword, keystorePath)
        }

        keystore
    }

    static boolean writeKeystore(KeyStore keystore, String keystorePassword, String keystorePath) {
        try {
            FileOutputStream fos = new FileOutputStream(keystorePath)
            keystore.store(fos, keystorePassword.chars)
            true
        } catch (IOException e) {
            logger.error("Error writing keystore to ${keystorePath}", e)
            false
        }
    }

    private static KeyStore addCAToKeystore(String dn, String alias, String keystorePassword, KeyStore keystore) {
        KeyPair caKeyPair = TlsToolkitUtil.generateKeyPair()
        X509Certificate caCertificate = CAService.generateCACertificate(caKeyPair, dn)
        keystore.setKeyEntry(alias, caKeyPair.private, keystorePassword.chars, [caCertificate] as Certificate[])
        keystore
    }

    private static KeyStore generateCAKeystore(String dn, String alias, String keystorePassword) {
        KeyStore keystore = KeyStore.getInstance("JKS")
        keystore.load(null, keystorePassword.chars)
        addCAToKeystore(dn, alias, keystorePassword, keystore)
    }

    private static KeyStore loadKeystoreContainingAlias(String keystorePath, String keystorePassword, String alias) {
        KeyStore keystore = KeyStore.getInstance("JKS")
        File keystoreFile = new File(keystorePath)
        if (keystoreFile.exists()) {
            keystore.load(keystoreFile.newInputStream(), keystorePassword.chars)
            if (keystore.containsAlias(alias)) {
                return keystore
            } else {
                def msg = "Keystore at ${keystorePath} did not contain alias ${alias}"
                logger.warn(msg)
                throw new KeyStoreException(msg)
            }
        } else {
            def msg = "Keystore at ${keystorePath} cannot be loaded"
            logger.warn(msg)
            throw new IOException(msg)
        }
    }

    private static Server createServer(Handler handler, int port, KeyStore keystore, String keyPassword) throws Exception {
        Server server = new Server()

        SslContextFactory sslContextFactory = new SslContextFactory()
        sslContextFactory.setIncludeProtocols("TLSv1.2")
        sslContextFactory.setKeyStore(keystore)
        sslContextFactory.setKeyManagerPassword(keyPassword)

        HttpConfiguration httpsConfig = new HttpConfiguration()
        httpsConfig.addCustomizer(new SecureRequestCustomizer())

        ServerConnector sslConnector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()), new HttpConnectionFactory(httpsConfig))
        sslConnector.setPort(port)
        logger.debug("Created Jetty server on port ${port}")

        server.addConnector(sslConnector)
        server.setHandler(handler)
        logger.debug("Added CA handler ${handler}")

        return server
    }

    synchronized void start() throws Exception {
        server?.start()
    }

    synchronized void shutdown() throws Exception {
        server?.stop()
        server?.join()
    }


    @Override
    String toString() {
        return "CAServer (v2)"
    }
}
