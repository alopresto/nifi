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

package org.apache.nifi.toolkit.tls.service.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.apache.nifi.toolkit.tls.configuration.TlsClientConfig;
import org.apache.nifi.toolkit.tls.manager.TlsClientManager;
import org.apache.nifi.toolkit.tls.manager.writer.JsonConfigurationWriter;
import org.apache.nifi.toolkit.tls.service.BaseCertificateAuthorityCommandLine;
import org.apache.nifi.toolkit.tls.standalone.TlsToolkitStandalone;
import org.apache.nifi.toolkit.tls.util.OutputStreamFactory;
import org.apache.nifi.toolkit.tls.util.TlsHelper;
import org.apache.nifi.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client that will generate a CSR and submit to a CA, writing out the results to a keystore and truststore along with a config file if successful
 */
public class TlsCertificateAuthorityClient {
    private final Logger logger = LoggerFactory.getLogger(TlsCertificateAuthorityClient.class);
    private final OutputStreamFactory outputStreamFactory;

    private boolean isVerbose = false;

    public TlsCertificateAuthorityClient() {
        this(FileOutputStream::new);
    }

    public TlsCertificateAuthorityClient(OutputStreamFactory outputStreamFactory) {
        this.outputStreamFactory = outputStreamFactory;
    }

    public void generateCertificateAndGetItSigned(TlsClientConfig tlsClientConfig, String certificateDirectory, String configJson, boolean differentKeyAndKeyStorePassword) throws Exception {
        // TODO: Why does TlsCertificateAuthorityClient use keystore rather than PEM files for CA?
        isVerbose = tlsClientConfig.isVerbose();

        // TODO: Refactor creation of TlsClientManager to separate method
        TlsClientManager tlsClientManager;
        try {
            tlsClientManager = new TlsClientManager(tlsClientConfig);
            if (isVerbose()) {
                logger.info("Created TLS client manager from client config");
            }
        } catch (IOException e) {
            // TODO: Why is this error thrown and why are these arguments necessary?
            logger.error("Unable to open existing keystore, it can be reused by specifying both " + BaseCertificateAuthorityCommandLine.CONFIG_JSON_ARG + " and " +
                    BaseCertificateAuthorityCommandLine.USE_CONFIG_JSON_ARG);
            throw e;
        }
        if (isVerbose()) {
            logger.info("Key password different from keystore password: " + differentKeyAndKeyStorePassword);
        }
        tlsClientManager.setDifferentKeyAndKeyStorePassword(differentKeyAndKeyStorePassword);

        // Validate the certificate directory path is not empty and set the accessor
        if (!StringUtils.isEmpty(certificateDirectory)) {
            final File certificateAuthorityDirectory = new File(certificateDirectory);
            tlsClientManager.setCertificateAuthorityDirectory(certificateAuthorityDirectory);
            if (isVerbose()) {
                logger.info("Set CA directory to " + certificateAuthorityDirectory.getAbsolutePath());
            }
        }

        // Validate the config.json path is not empty and set the accessor
        if (!StringUtils.isEmpty(configJson)) {
            final File configJsonFile = new File(configJson);
            tlsClientManager.addClientConfigurationWriter(new JsonConfigurationWriter<>(new ObjectMapper(), configJsonFile));
            if (isVerbose()) {
                logger.info("Set output config JSON file to " + configJsonFile.getAbsolutePath());
            }
        }

        // TODO: Is this generating the CA certificate? Where is the DN set? In the TlsClientConfig?
        // Check that the nifi-key alias does not exist in the (wrapped) keystore
        if (tlsClientManager.getEntry(TlsToolkitStandalone.NIFI_KEY) == null) {
            if (isVerbose()) {
                // TODO: This CA hostname is stored separately from the alias certificate and could mismatch
                logger.info("Requesting new certificate from " + tlsClientConfig.getCaHostname() + ":" + tlsClientConfig.getPort());
            }

            // Generate the new certificate key pair
            KeyPair keyPair = TlsHelper.generateKeyPair(tlsClientConfig.getKeyPairAlgorithm(), tlsClientConfig.getKeySize());
            if (isVerbose()) {
                logger.info("Created " + tlsClientConfig.getKeyPairAlgorithm() + " key pair with length " + tlsClientConfig.getKeySize());
            }

            // TODO: Refactor into discrete steps
            // Create the CSR, submit it for signature, and return the certificate chain
            X509Certificate[] certificates = tlsClientConfig.createCertificateSigningRequestPerformer().perform(keyPair);
            if (isVerbose()) {
                logger.info("Created CSR and CA signed it");
                logger.info("Received signed certificate chain of length " + certificates.length);
                for (X509Certificate certificate : certificates) {
                    logger.info("Certificate: " + certificate.getSubjectX500Principal().getName());
                    logger.info("\tSAN: " + TlsHelper.formatSANForDisplay(certificate));
                    logger.info("\tSigned by: " + certificate.getIssuerX500Principal().getName());
                }
            }

            // Puts the new private key into the keystore with the "nifi-key" alias
            tlsClientManager.addPrivateKeyToKeyStore(keyPair, TlsToolkitStandalone.NIFI_KEY, certificates);
            if (isVerbose()) {
                logger.info("Inserted CA private key and certificates into keystore with alias " + TlsToolkitStandalone.NIFI_KEY);
            }

            // Puts the certificate chain (except the root, which is the same certificate [self-signed]) into the truststore with the "nifi-cert" alias
            final int certificateChainLengthExceptRoot = certificates.length - 1;
            tlsClientManager.setCertificateEntry(TlsToolkitStandalone.NIFI_CERT, certificates[certificateChainLengthExceptRoot]);
            if (isVerbose()) {
                logger.info("Inserted " + certificateChainLengthExceptRoot + " certificates into truststore with alias " + TlsToolkitStandalone.NIFI_CERT);
            }
        } else {
            if (isVerbose()) {
                // TODO: What does this mean?
                logger.info("Already had entry for " + TlsToolkitStandalone.NIFI_KEY + " not requesting new certificate.");
            }
        }

        tlsClientManager.write(outputStreamFactory);
        if (isVerbose()) {
            logger.info("Wrote something to output stream factory?");
        }
    }

    protected boolean isVerbose() {
        return isVerbose;
    }
}
