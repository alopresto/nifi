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

import org.apache.commons.cli.CommandLine
import org.apache.commons.cli.CommandLineParser
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.HelpFormatter
import org.apache.commons.cli.Option
import org.apache.commons.cli.Options
import org.apache.commons.cli.ParseException
import org.apache.nifi.toolkit.tls.commandLine.CommandLineParseException
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyStore
import java.security.Security

class CAServerRunner {
    private static final Logger logger = LoggerFactory.getLogger(CAServerRunner.class)

    static final String HELP_ARG = "help"
    static final String VERBOSE_ARG = "verbose"

    // Key loading values
    static final String KEYSTORE_PATH_ARG = "keystorePath"
    static final String KEYSTORE_PASSWORD_ARG = "keystorePassword"
    static final String CA_ALIAS_ARG = "caAlias"
    static final String EXTERNAL_CA_CERT_PATH_ARG = "externalCert"
    static final String EXTERNAL_CA_KEY_PATH_ARG = "externalKey"

    // Key generation values
    static final String CERT_DN_ARG = "certificateDn"
    static final String CERT_SANS_ARG = "subjectAlternativeNames"

    // Communication values
    static final String TOKEN_ARG = "token"
    static final String PORT_ARG = "port"

    // Optional signing config values
    static final String CERT_DAYS_ARG = "daysValid"
    static final String ALGORITHM_ARG = "algorithm"
    static final String SIGNING_ALGORITHM_ARG = "signingAlgorithm"

    // Java path constants
    static final String JAVA_HOME = "JAVA_HOME"
    static final String NIFI_TOOLKIT_HOME = "NIFI_TOOLKIT_HOME"
    static final String SEP = System.lineSeparator()
    private static final String FOOTER = buildFooter()
    private static final int MIN_TOKEN_LENGTH = 16

    private static
    final String DEFAULT_DESCRIPTION = "This tool starts a CA server running on the specified port. Type 'stop' to shutdown the server, or kill the process with Ctrl + C"

    // Static holder to avoid re-generating the options object multiple times in an invocation
    private static Options staticOptions

    private static BufferedReader shutdownReader = System.in.newReader()

    private static final String DEFAULT_CA_ALIAS = "nifi-key"
    private static final String DEFAULT_CA_DN = "CN=nifi-ca, OU=NiFi"
    private static final int DEFAULT_PORT = 14443

    private static String buildHeader(String description = DEFAULT_DESCRIPTION) {
        "${SEP}${description}${SEP * 2}"
    }

    private static String buildFooter() {
        "${SEP}Java home: ${System.getenv(JAVA_HOME)}${SEP}NiFi Toolkit home: ${System.getenv(NIFI_TOOLKIT_HOME)}"
    }

    private final Options options
    private final String header

    // Instance values
    private boolean isVerbose = false

    // Key loading values
    private String keystorePath
    private String keystorePassword
    private String caAlias = DEFAULT_CA_ALIAS
    private String externalCertPath
    private String externalKeyPath

    // Key generation values
    private String certDn = DEFAULT_CA_DN
    private String certSans = ""

    // Communication values
    private String token
    private int port = DEFAULT_PORT

    // Optional config values
    private int certDays = TlsToolkitUtil.DEFAULT_CERT_VALIDITY_DAYS
    private String algorithm = TlsToolkitUtil.DEFAULT_ALGORITHM
    private String signingAlgorithm = TlsToolkitUtil.DEFAULT_SIGNING_ALGORITHM

    CAServerRunner() {
        this(DEFAULT_DESCRIPTION)
    }

    CAServerRunner(String description) {
//        logger.metaClass.methodMissing = { String name, args ->
//            String argsToPrint = (args as List).join(" ")
//            switch (name.toLowerCase()) {
//                case "debug":
//                    if (isVerbose) {
//                        logger.debug(argsToPrint)
//                    }
//                    break
//                default:
//                    if (logger.respondsTo(name)) {
//                        logger."$name"(argsToPrint)
//                    } else {
//                        logger.info("[${name?.toUpperCase()}] ${argsToPrint}")
//                    }
//            }
//        }

        this.header = buildHeader(description)
        this.options = getCliOptions()
    }

    static Options buildOptions() {
        // TODO: Build OptionGroups with mutually-exclusive Options

        Options options = new Options()
        options.addOption(Option.builder("h").longOpt(HELP_ARG).hasArg(false).desc("Show usage information (this message)").build())
        options.addOption(Option.builder("v").longOpt(VERBOSE_ARG).hasArg(false).desc("Sets verbose mode (default false)").build())

        // Key loading values
        options.addOption(Option.builder("k").longOpt(KEYSTORE_PATH_ARG).hasArg(true).argName("file").desc("The JKS file containing the CA certificate and private key (keystore.jks)").build())
        options.addOption(Option.builder("P").longOpt(KEYSTORE_PASSWORD_ARG).hasArg(true).argName("password").desc("The keystore.jks password").build())
        options.addOption(Option.builder("A").longOpt(CA_ALIAS_ARG).hasArg(true).argName("alias").desc("The alias in the keystore (nifi-key)").build())
        options.addOption(Option.builder("c").longOpt(EXTERNAL_CA_CERT_PATH_ARG).hasArg(true).argName("file").desc("The PEM encoded CA public certificate (ca.crt, nifi-cert.pem)").build())
        options.addOption(Option.builder("K").longOpt(EXTERNAL_CA_KEY_PATH_ARG).hasArg(true).argName("file").desc("The PEM encoded CA private key (ca-key.pem, nifi-key.key)").build())

        // Key generation values
        options.addOption(Option.builder("d").longOpt(CERT_DN_ARG).hasArg(true).argName("DN").desc("The desired CA cert DN (CN=nifi-ca, OU=NiFi)").build())
        options.addOption(Option.builder("s").longOpt(CERT_SANS_ARG).hasArg(true).argName("SAN1, SAN2, etc.").desc("The desired CA cert SANS (localhost, 127.0.0.1)").build())

        // Communication values
        options.addOption(Option.builder("t").longOpt(TOKEN_ARG).hasArg(true).argName("token").desc("The MITM token required of clients (min 16 chars)").build())
        options.addOption(Option.builder("p").longOpt(PORT_ARG).hasArg(true).argName("port").desc("The port to run the server on (14443)").build())

        // Optional signing values
        options.addOption(Option.builder("D").longOpt(CERT_DAYS_ARG).hasArg(true).argName("days").desc("The number of days to make signed certificates valid (1095)").build())
        options.addOption(Option.builder("a").longOpt(ALGORITHM_ARG).hasArg(true).argName("algorithm").desc("The certificate algorithm to use (RSA)").build())
        options.addOption(Option.builder("S").longOpt(SIGNING_ALGORITHM_ARG).hasArg(true).argName("algorithm").desc("The signing algorithm to use (SHA256withRSA)").build())

        options
    }

    static Options getCliOptions() {
        if (!staticOptions) {
            staticOptions = buildOptions()
        }
        return staticOptions
    }

    /**
     * Prints the usage message and available arguments for this tool (along with a specific error message if provided).
     *
     * @param errorMessage the optional error message
     */
    void printUsage(String errorMessage) {
        if (errorMessage) {
            System.out.println(errorMessage)
            System.out.println()
        }
        HelpFormatter helpFormatter = new HelpFormatter()
        helpFormatter.setWidth(160)
        helpFormatter.setOptionComparator(null)
        // preserve manual ordering of options when printing instead of alphabetical
        helpFormatter.printHelp(CAServerRunner.class.getCanonicalName(), header, options, FOOTER, true)
    }

    protected void printUsageAndThrow(String errorMessage) throws ParseException {
        printUsage(errorMessage)
        throw new ParseException(errorMessage)
    }

    /**
     * Parses the provided command-line arguments into the proper instance values. Validates parameters (presence and format, not file existence/validity).
     *
     * @param args the args from the invocation
     * @return the {@link CommandLine} object containing the parsed values
     * @throws CommandLineParseException
     */
    protected CommandLine parse(String[] args) throws CommandLineParseException {
        CommandLineParser parser = new DefaultParser()
        CommandLine commandLine
        try {
            commandLine = parser.parse(options, args)
            if (commandLine.hasOption(HELP_ARG)) {
                printUsage()
                System.exit(0)
            }

            isVerbose = commandLine.hasOption(VERBOSE_ARG)

            // Key loading values
            keystorePath = commandLine.getOptionValue(KEYSTORE_PATH_ARG)
            keystorePassword = commandLine.getOptionValue(KEYSTORE_PASSWORD_ARG)
            caAlias = commandLine.getOptionValue(CA_ALIAS_ARG, DEFAULT_CA_ALIAS)
            externalCertPath = commandLine.getOptionValue(EXTERNAL_CA_CERT_PATH_ARG)
            externalKeyPath = commandLine.getOptionValue(EXTERNAL_CA_KEY_PATH_ARG)

            // Key generation values
            certDn = commandLine.getOptionValue(CERT_DN_ARG, DEFAULT_CA_DN)
            certSans = commandLine.getOptionValue(CERT_SANS_ARG)

            // Communication values
            token = commandLine.getOptionValue(TOKEN_ARG)
            port = commandLine.getOptionValue(PORT_ARG, DEFAULT_PORT as String) as int

            // Optional config values
            certDays = commandLine.getOptionValue(CERT_DAYS_ARG, TlsToolkitUtil.DEFAULT_CERT_VALIDITY_DAYS as String) as int
            algorithm = commandLine.getOptionValue(ALGORITHM_ARG)
            signingAlgorithm = commandLine.getOptionValue(SIGNING_ALGORITHM_ARG)

            // TODO: Config.json (later)

            // TODO: Encrypted External CA key file (requires password arg)

            if (isVerbose) {
                printArguments(commandLine)
            }

            // Check parameter validity
            validateParameters()

            return commandLine
        } catch (ParseException e) {
            if (isVerbose) {
                logger.error("Encountered an error parsing command line", e)
            }
            printUsageAndThrow("Error parsing command line. (" + e.getMessage() + ")")
        }
    }

    void printArguments(CommandLine commandLine) {
        options.getOptions().each { Option opt ->
            logger.info(opt.longOpt.padRight(25) + getValueForDisplay(commandLine, opt))
        }
    }

    static String getValueForDisplay(CommandLine cl, Option opt) {
        if (opt.longOpt.toLowerCase().contains("password")) {
            String password = cl.getOptionValue(opt.longOpt)
            return (cl.hasOption(opt.longOpt) ? '*' * password.length() : "null")
        } else {
            (cl.getOptionValue(opt.longOpt) ?: "null")
        }
    }

    void validateParameters() {
        if (!token || token.size() < MIN_TOKEN_LENGTH) {
            printUsageAndThrow("The token must be provided and must be at least 16 characters")
        }

        if (!keystorePath || !keystorePassword) {
            logger.debug("No keystore or keystore password provided, checking external CA files")

            if (!externalCertPath || !externalKeyPath) {
                logger.info("If keystore and keystore password are not provided, the CA cert and key must be")
                printUsageAndThrow("Must provide external CA cert and key files")
            }
        } else {
            logger.debug("Using keystore and keystore password")
        }

    }

    // TODO: Switch logger statements to dynamic print()
    private void print(String msg, String level = "INFO") {
        switch (level.toUpperCase()) {
            case "DEBUG":
                if (isVerbose) {
                    logger.debug(msg)
                }
                break
            default:
                def methodName = level.toLowerCase()
                if (logger.respondsTo(methodName)) {
                    logger."$methodName"(msg)
                } else {
                    logger.warn("Logger does not respond to ${methodName}, using INFO")
                    logger.info(msg)
                }
        }
    }

    // Reads config.json (later)

    // TODO: Use parameters with default value referencing instance fields to allow overriding

    // Loads or generates CA keystore
    KeyStore prepareKeystore() {
        KeyStore keystore = TlsToolkitUtil.generateOrLocateKeystore(keystorePath, keystorePassword, caAlias, certDn)
        logger.info("Loaded CA keystore at ${keystorePath} with CA cert for ${certDn} in alias ${caAlias}")
        keystore
    }

    // Configures server
    NiFiCAServer createServer() {
        NiFiCAServer caServer = new NiFiCAServer(port, keystorePath, keystorePassword, token, caAlias, certDn)
        logger.info("Created CA server: ${caServer}")
        caServer
    }

    // Starts server

    static boolean waitForShutdown(BufferedReader reader) {
        while (true) {
            if (reader.readLine() == "stop") {
                return true
            }
            logger.debug("No shutdown command received; sleep 5 s")
            Thread.sleep(5000)
        }
    }

    // Main

    /**
     * Runs main tool logic (parsing arguments, running server).
     *
     * @param args the command-line arguments
     */
    static void main(String[] args) {
        // TODO: Comment out after testing
        System.out.println("Invoked with args: " + args)

        Security.addProvider(new BouncyCastleProvider())

        CAServerRunner runner = new CAServerRunner()

        try {
            try {
                // Parse the flags into fields
                runner.parse(args)
            } catch (Exception e) {
                if (runner.isVerbose) {
                    logger.error("Encountered an error", e)
                }
                runner.printUsageAndThrow(e.message)
            }
        } catch (ParseException e) {
            System.exit(1)
        }

        // Start runner

        runner.prepareKeystore()
        NiFiCAServer caServer = runner.createServer()
        caServer.start()

        boolean shutdownCalled = waitForShutdown(shutdownReader)
        logger.info("Shutdown command received")

        caServer.shutdown()
        System.exit(0)

        // Shutdown gracefully?

//        System.exit(ExitCode.SUCCESS.ordinal())
    }
}
