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

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.apache.nifi.toolkit.tls.v2.ca.CAService
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.Response
import org.eclipse.jetty.server.handler.AbstractHandler
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.security.GeneralSecurityException
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/**
 * Jetty handler to perform the CSR signing.
 */
class CAHandler extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(CAHandler.class)

    CAService caService

    CAHandler(CAService cas) {
        this.caService = cas
        logger.info("Created a CA handler with ${cas}")
    }

    /**
     * Accepts a JSON payload in the request body containing a PEM-encoded (Base64) CSR and the generated HMAC/ SHA-256(token, CSR public key) and sends a response containing the PEM-encoded certificate chain, including the CA cert and signed leaf cert. If an exception occurs, sends an error response containing a JSON payload with descriptive errors.
     *
     * @param s the target
     * @param request the base request
     * @param httpServletRequest the request containing the payload
     * @param httpServletResponse the response containing the payload
     * @throws IOException
     * @throws ServletException
     */
    @Override
    void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
        logger.info("Received CSR signing request ${s} from ${httpServletRequest.remoteAddr}")
        String csrDn = "unable to parse CSR subject"

        try {
            // Parse the incoming request and extract the body (JSON containing Base64-encoded CSR and HMAC)
            Map parsedJson = extractRequestJson(httpServletRequest)

            String hmac = parsedJson.hmac
            logger.debug("Extracted HMAC from request: ${hmac}")

            JcaPKCS10CertificationRequest csr = decodeCsrFromJson(parsedJson)
            csrDn = csr.subject

            // Try to sign the CSR
            String chainBase64 = signAndEncodeCertificateChain(csr, hmac)

            // Form the response
            String responseJson = formSuccessResponseJson(csrDn, chainBase64)

            // Send the response
            httpServletResponse.setContentType("application/json")
            httpServletResponse.writer.write(responseJson)
            httpServletResponse.setStatus(Response.SC_OK)
        } catch (GeneralSecurityException e) {
            logger.error("Encountered a problem signing the CSR -- ${e.message}")

            // Form the response
            String responseJson = formErrorResponseJson(csrDn, e.message)

            // Send the response
            httpServletResponse.setContentType("application/json")
            httpServletResponse.writer.write(responseJson)
            httpServletResponse.setStatus(Response.SC_FORBIDDEN)
        }

        // Required or a 404 will be returned
        request.setHandled(true)
    }

    protected String formSuccessResponseJson(String csrDn, String chainBase64) {
        // Form response map
        Map responseMap = [
                message         : "Successfully signed certificate for ${csrDn} with CA ${getCACertName()}",
                certificateChain: chainBase64
        ]

        // Form response JSON
        String responseJson = JsonOutput.toJson(responseMap)
        logger.debug("Formed response JSON: ${responseJson}")
        responseJson
    }

    protected String formErrorResponseJson(String csrDn, String errorMessage) {
        // Form response map
        Map responseMap = [
                message     : "Unable to sign ${csrDn} with CA ${getCACertName()}",
                errorMessage: errorMessage
        ]

        // Form response JSON
        String responseJson = JsonOutput.toJson(responseMap)
        logger.debug("Formed response JSON: ${responseJson}")
        responseJson
    }

    private String getCACertName() {
        caService.caCert.subjectX500Principal.name
    }

    protected String signAndEncodeCertificateChain(JcaPKCS10CertificationRequest csr, String hmac) {
        X509Certificate signedCertificate = caService.signCSR(csr, hmac)
        logger.info("Signed the certificate for ${csr.subject}")

        // Concat the signed certificate and the CA certificate
        List<Certificate> certificateChain = [caService.caCert, signedCertificate]
        logger.info("Formed the certificate chain [${certificateChain*.subjectX500Principal.name.join(" -> ")}] to return")

        // Base64 encode the certificate chain
        String chainBase64 = certificateChain.collect { Certificate cert ->
            TlsToolkitUtil.pemEncode(cert)
        }.join()
        logger.info("Encoded the certificate chain to PEM: ${chainBase64}")
        chainBase64
    }

    protected static JcaPKCS10CertificationRequest decodeCsrFromJson(Map parsedJson) {
        String csrBase64 = parsedJson.csr
        logger.debug("Extracted CSR in Base64 encoding: ${csrBase64}")

        // Decode the CSR
        JcaPKCS10CertificationRequest csr = TlsToolkitUtil.decodeCsr(csrBase64)
        logger.debug("Decoded PEM CSR for DN: ${csr.subject}")
        csr
    }

    protected static Map extractRequestJson(HttpServletRequest httpServletRequest) {
        String jsonContents = httpServletRequest.reader.readLines().join(System.lineSeparator())
        logger.debug("Read JSON contents: ${jsonContents}")

        Map parsedJson = new JsonSlurper().parseText(jsonContents) as Map
        logger.debug("Parsed request JSON to keys: ${parsedJson.keySet()}")
        parsedJson
    }
}
