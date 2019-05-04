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
    static final int DEFAULT_PORT = 14443
    private static final int KEYSTORE_PASSWORD_LENGTH = 30

    private Server server

    CAServer(int port = DEFAULT_PORT, String keystorePath = DEFAULT_KEYSTORE_PATH, String keystorePassword, String token, String alias = TlsToolkitUtil.DEFAULT_ALIAS, String dn = TlsToolkitUtil.DEFAULT_DN) {
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

    // TODO: Move to CAServerRunner (not the responsibility of the server to build the keystore)
    /**
     * Instantiates a {@code CAServer} using PEM-encoded certificate and key files. The {@link File}s are passed rather than {@code String} paths to differentiate the constructors.
     *
     * @param port the port to run on
     * @param externalCACertFile the *.crt or *.pem CA public certificate
     * @param externalCAKeyFile the *.key or *.pem CA private key (no password)
     * @param token the MITM token
     */
    CAServer(int port = DEFAULT_PORT, File externalCACertFile, File externalCAKeyFile, String token) {
        // Generate a random password for the keystore and output it in the logs
        String keystorePassword = TlsToolkitUtil.generateRandomPassword(KEYSTORE_PASSWORD_LENGTH)
        logger.debug("Generated password of length ${keystorePassword.length()} for new keystore")

        String pemEncodedCert = externalCACertFile.text
        logger.debug("Read public certificate from ${externalCACertFile.path}")

        String pemEncodedKey = externalCAKeyFile.text
        logger.debug("Read private key from ${externalCAKeyFile.path}")


        X509Certificate externalCACert = TlsToolkitUtil.decodeCertificate(pemEncodedCert)
        PrivateKey externalCAKey = TlsToolkitUtil.parsePem(PrivateKey.class, pemEncodedKey)

        // Generate a keystore containing the external cert and key under the default alias
        KeyStore keystore = TlsToolkitUtil.generateKeystoreFromExternalMaterial(externalCACert, externalCAKey, keystorePassword, TlsToolkitUtil.DEFAULT_ALIAS)

        // Persist the keystore in the default location
        // TODO: Write file out

        // Create the CA service
        CAService caService = createCAService(keystore, keystorePassword, token, TlsToolkitUtil.DEFAULT_ALIAS)
        CAHandler caHandler = new CAHandler(caService)
        this.server = createServer(caHandler, port, keystore, keystorePassword)
    }

    // TODO: Add KeyStore generator for external CA?
    // TODO: Or inject different CAService impls based on signing material?

    static CAService createCAService(KeyStore keystore, String keyPassword, String token, String alias) {
        PrivateKey privateKey = keystore.getKey(alias, keyPassword.chars) as PrivateKey
        X509Certificate caCert = keystore.getCertificate(alias) as X509Certificate
        PublicKey publicKey = caCert.publicKey
        new CAService(token, publicKey, privateKey, caCert)
    }

    /**
     * Returns a {@link KeyStore} containing the CA certificate and private key. If the keystore already exists at the provided path and contains the key under the specified alias, it simply loads and returns it. If the keystore does not exist, or if it exists but does not contain the key under the alias, a new key and certificate are generated and stored, and the updated file is written out to the provided path.
     *
     * @param keystorePath the location of the keystore
     * @param keystorePassword the keystore password
     * @param alias the alias to check / persist
     * @param dn the DN of the CA certificate if a new one must be generated
     * @return the populated keystore
     */
    static KeyStore generateOrLocateKeystore(String keystorePath, String keystorePassword, String alias, String dn) {
        KeyStore keystore

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
