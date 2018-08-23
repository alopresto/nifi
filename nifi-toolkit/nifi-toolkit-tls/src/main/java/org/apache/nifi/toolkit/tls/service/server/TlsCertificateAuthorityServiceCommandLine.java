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

package org.apache.nifi.toolkit.tls.service.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.apache.nifi.toolkit.tls.commandLine.CommandLineParseException;
import org.apache.nifi.toolkit.tls.commandLine.ExitCode;
import org.apache.nifi.toolkit.tls.configuration.TlsConfig;
import org.apache.nifi.toolkit.tls.service.BaseCertificateAuthorityCommandLine;
import org.apache.nifi.toolkit.tls.util.InputStreamFactory;
import org.apache.nifi.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command line parser for a TlsConfig object and a main entry point to invoke the parser and run the CA server
 */
public class TlsCertificateAuthorityServiceCommandLine extends BaseCertificateAuthorityCommandLine {
    private static final Logger logger = LoggerFactory.getLogger(TlsCertificateAuthorityServiceCommandLine.class);

    public static final String DESCRIPTION = "Acts as a Certificate Authority that can be used by clients to get Certificates";
    public static final String NIFI_CA_KEYSTORE = "nifi-ca-" + KEYSTORE;
    private static final int TOKEN_MIN_LENGTH = 16;

    private TlsCertificateAuthorityService caService;


    private final InputStreamFactory inputStreamFactory;
    private final String DEFAULT_CA_HOSTNAME = "YOUR_CA_HOSTNAME";

    public TlsCertificateAuthorityServiceCommandLine() {
        this(FileInputStream::new);
    }

    public TlsCertificateAuthorityServiceCommandLine(InputStreamFactory inputStreamFactory) {
        super(DESCRIPTION);
        this.inputStreamFactory = inputStreamFactory;
    }

    public static void main(String[] args) throws Exception {
        TlsCertificateAuthorityServiceCommandLine commandLine = new TlsCertificateAuthorityServiceCommandLine();
        try {
            commandLine.parse(args);
        } catch (CommandLineParseException e) {
            System.exit(e.getExitCode().ordinal());
        }
        if (commandLine.isVerbose()) {
            logger.info("Completed parsing command-line arguments");
        }

        try {
            commandLine.validateParameters();
        } catch (Exception e) {
            commandLine.printUsageAndThrow(e.getMessage(), ExitCode.INVALID_ARGS);
        }

        commandLine.configureCAService(new TlsCertificateAuthorityService());

        commandLine.startCAService();
    }

    /**
     * Returns true if the parameters parsed from the command line arguments are valid. If not, will throw an exception.
     * @return true if the parameters are valid
     */
    boolean validateParameters() {
        // Validate parameters
        final String token = getToken();
        if (StringUtils.isBlank(token) || token.length() < TOKEN_MIN_LENGTH) {
            final String msg = "The provided token must be at least " + TOKEN_MIN_LENGTH + " characters";
            if (isVerbose()) {
                logger.error(msg + " and provided token is " + (token == null ? "0" : token.length()) + " characters");
            }
            throw new IllegalArgumentException(msg);
        }

        return true;
    }

    /**
     * Starts the CA service.
     *
     * @throws Exception
     */
    private void startCAService() throws Exception {
        caService.start(createConfig(), getConfigJsonOut(),
                differentPasswordForKeyAndKeystore());
        logger.info("CA server started");
    }

    /**
     * Sets the {@code caService} field (if {@code null}) to the provided service instance. Otherwise, does nothing.
     *
     * @param tlsCertificateAuthorityService an instance of a CA service
     */
    private void configureCAService(TlsCertificateAuthorityService tlsCertificateAuthorityService) {
        if (this.caService == null) {
            caService = tlsCertificateAuthorityService;
            if (isVerbose()) {
                logger.info("Created CA service using {}", caService.getClass().getName());
            }
        } else {
            if (isVerbose()) {
                logger.info("CA service already configured using {}", caService.getClass().getName());
            }
        }
    }

    public TlsConfig createConfig() throws IOException {
        String configJsonIn = getConfigJsonIn();
        if (!StringUtils.isEmpty(configJsonIn)) {
            try (InputStream inputStream = inputStreamFactory.create(new File(configJsonIn))) {
                TlsConfig tlsConfig = new ObjectMapper().readValue(inputStream, TlsConfig.class);
                tlsConfig.initDefaults();
                return tlsConfig;
            }
        } else {
            TlsConfig tlsConfig = new TlsConfig();
            tlsConfig.setCaHostname(getCertificateAuthorityHostname());
            tlsConfig.setDn(getDn());
            tlsConfig.setToken(getToken());
            tlsConfig.setPort(getPort());
            tlsConfig.setKeyStore(NIFI_CA_KEYSTORE + getKeyStoreType().toLowerCase());
            tlsConfig.setKeyStoreType(getKeyStoreType());
            tlsConfig.setKeySize(getKeySize());
            tlsConfig.setKeyPairAlgorithm(getKeyAlgorithm());
            tlsConfig.setSigningAlgorithm(getSigningAlgorithm());
            tlsConfig.setDays(getDays());
            return tlsConfig;
        }
    }

    @Override
    protected String getTokenDescription() {
        return "The token to use to prevent MITM (required and must be same as one used by clients)";
    }

    @Override
    protected String getDnDescription() {
        return "The dn to use for the CA certificate";
    }

    @Override
    protected String getPortDescription() {
        return "The port for the Certificate Authority to listen on";
    }

    @Override
    protected String getDnHostname() {
        String dnHostname = getCertificateAuthorityHostname();
        if (StringUtils.isEmpty(dnHostname)) {
            if (isVerbose()) {
                logger.warn("No CA hostname provided; returning default " + DEFAULT_CA_HOSTNAME);
            }
            return DEFAULT_CA_HOSTNAME;
        }
        return dnHostname;
    }
}
