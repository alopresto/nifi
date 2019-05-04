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

package org.apache.nifi.toolkit.tls.v2.ca

import org.apache.nifi.toolkit.tls.v2.util.TlsToolkitUtil
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest

import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * This interface defines method contracts for implementing certificate authorities. A valid implementation must make its public certificate available for consumption, and must provide a mechanism to sign a CSR.
 */
interface CAService {
    /**
     * Returns the public {@link X509Certificate} of this Certificate Authority (CA).
     *
     * @return the public CA certificate
     */
    X509Certificate getCaCert()

    /**
     * Returns the signed {@link X509Certificate} generated from the Certificate Signing Request (CSR). The provided HMAC value must be validated internally, or a {@link GeneralSecurityException} will be thrown.
     *
     * @param csr the certificate signing request
     * @param providedHmac the calculated HMAC. See {@link TlsToolkitUtil#calculateHMac(String, PublicKey)}
     * @param signingAlgorithm the signing algorithm (i.e. "SHA256withRSA")
     * @param certDaysValid the desired validity of the certificate in days (i.e. 365)
     * @return the public certificate signed by this CA's private key
     */
    X509Certificate signCSR(JcaPKCS10CertificationRequest csr, String providedHmac, String signingAlgorithm, int certDaysValid)
}