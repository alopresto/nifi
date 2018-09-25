package org.apache.nifi.toolkit.tls.v2.server

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.apache.nifi.toolkit.tls.v2.ca.CAService
import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.handler.AbstractHandler
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.security.GeneralSecurityException
import java.security.cert.Certificate
import java.security.cert.X509Certificate

class CAHandler extends AbstractHandler {
    private static final Logger logger = LoggerFactory.getLogger(CAHandler.class)

    CAService caService

    CAHandler(CAService cas) {
        this.caService = cas
        logger.info("Created a CA handler with ${cas}")
    }

    @Override
    void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {
        logger.info("Received CSR signing request ${s} from ${httpServletRequest.remoteAddr}")

        // Parse the incoming request and extract the body (JSON containing Base64-encoded CSR)
        String jsonContents = httpServletRequest.reader.readLines().join(System.lineSeparator())
        logger.debug("Read JSON contents: ${jsonContents}")

        Map parsedJson = new JsonSlurper().parseText(jsonContents) as Map
        logger.debug("Parsed request JSON to keys: ${parsedJson.keySet()}")

        String hmac = parsedJson.hmac
        logger.debug("Extracted HMAC from request: ${hmac}")
        String csrBase64 = parsedJson.csr
        logger.debug("Extracted CSR in Base64 encoding: ${csrBase64}")

        // Decode the CSR
//        byte[] csrBytes = Base64.decoder.decode(csrBase64)
        JcaPKCS10CertificationRequest csr = TlsToolkitUtil.decodeCsr(csrBase64)
        logger.debug("Decoded PEM CSR for DN: ${csr.subject}")

        // Try to sign the CSR
        try {
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

            // Form response map
            Map responseMap = [message: "Successfully signed certificate for ${csr.subject} with CA ${caService.caCert.subjectX500Principal.name}",
                               certificateChain: chainBase64]

            // Form response JSON
            String responseJson = JsonOutput.toJson(responseMap)
            logger.debug("Formed response JSON: ${responseJson}")

            // Send as response
            httpServletResponse.writer.write(responseJson)
        } catch (GeneralSecurityException e) {
            logger.error("Encountered a problem signing the CSR -- the provided HMAC is invalid")
            throw new ServletException(e) // ?
        }

        // Send the response

        // TODO: Send 50x response
    }
}
