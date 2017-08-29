/*
 *    Copyright 2014 - 2017 Yannick Watier
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package ca.watier;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.junit.Assert;
import org.junit.Test;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.x509.X500Name;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class KeystoreGeneratorTest {
    private static final String GIVEN_NAME = "given name";
    private static final String ORGANIZATION = "organization";
    private static final String ORGANIZATIONAL_UNIT_NAME = "organizational unit name";
    private static final String COMMON_NAME = "common name";
    private final Map<ASN1ObjectIdentifier, String> CERT_USER_INFOS;
    public KeystoreGeneratorTest() {
        CERT_USER_INFOS = new HashMap<>();
        CERT_USER_INFOS.put(BCStyle.GIVENNAME, GIVEN_NAME);
        CERT_USER_INFOS.put(BCStyle.O, ORGANIZATION);
        CERT_USER_INFOS.put(BCStyle.OU, ORGANIZATIONAL_UNIT_NAME);
        CERT_USER_INFOS.put(BCStyle.CN, COMMON_NAME);
    }

    @Test
    public void createEcWithDefaultCurveKeystoreAndPassword() throws Exception {
        String mainSigningAlgSha512Ec = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_EC;

        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createEcWithDefaultCurveKeystoreAndPassword(
                        mainSigningAlgSha512Ec,
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        ECPrivateKeyImpl key = (ECPrivateKeyImpl) keyStore.getKey(KeystoreGenerator.ALIAS, password.toCharArray());
        String curveName = getEcCurveName(key);

        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        Assert.assertEquals("P-384", curveName); //P-384 == secp384r1

        assertCertUserInfos(x500name);
        Assert.assertEquals(mainSigningAlgSha512Ec, certificate.getSigAlgName());
        assertThat(password).isNotEmpty().hasSize(64);
    }

    @Test
    public void createEcKeystore() throws Exception {
        String keystorePwd = "changeMyPassword!";
        String mainSigningAlgSha512Ec = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_EC;

        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createEcKeystore(
                        mainSigningAlgSha512Ec,
                        "sect571r1",
                        keystorePwd,
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        PrivateKey key = (PrivateKey) keyStore.getKey(KeystoreGenerator.ALIAS, keystorePwd.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        assertCertUserInfos(x500name);
        Assert.assertEquals(mainSigningAlgSha512Ec, certificate.getSigAlgName());
        Assert.assertEquals("EC", key.getAlgorithm());
        Assert.assertEquals(keystorePwd, password);
    }

    private void assertCertUserInfos(X500Name x500name) throws IOException {
        Assert.assertEquals(GIVEN_NAME, x500name.getGivenName());
        Assert.assertEquals(ORGANIZATION, x500name.getOrganization());
        Assert.assertEquals(ORGANIZATIONAL_UNIT_NAME, x500name.getOrganizationalUnit());
        Assert.assertEquals(COMMON_NAME, x500name.getCommonName());
    }

    @Test
    public void createEcKeystoreWithGeneratedPassword() throws Exception {
        String mainSigningAlgSha512Ec = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_EC;

        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createEcKeystore(
                        mainSigningAlgSha512Ec,
                        "sect571r1",
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        ECPrivateKeyImpl key = (ECPrivateKeyImpl) keyStore.getKey(KeystoreGenerator.ALIAS, password.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);
        String curveName = getEcCurveName(key);

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        Assert.assertEquals("B-571", curveName); //B-571 == sect571r1

        assertCertUserInfos(x500name);
        Assert.assertEquals(mainSigningAlgSha512Ec, certificate.getSigAlgName());
        Assert.assertEquals("EC", key.getAlgorithm());
        assertThat(password).isNotEmpty().hasSize(64);
    }

    private String getEcCurveName(ECPrivateKeyImpl key) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        //Access the class NamedCurve (hidden) to get the curve Oid
        Class<?> aClass = Class.forName("sun.security.ec.NamedCurve");
        Object namedCurve = aClass.cast(key.getParams());
        Method getObjectId = aClass.getDeclaredMethod("getObjectId");
        getObjectId.setAccessible(true);
        String curveOid = (String) getObjectId.invoke(namedCurve);

        return ECNamedCurveTable.getName(new ASN1ObjectIdentifier(curveOid));
    }

    @Test
    public void createEcWithDefaultCurveKeystore() throws Exception {
        String keystorePwd = "changeMyPassword!";
        String mainSigningAlgSha512Ec = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_EC;

        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createEcWithDefaultCurveKeystore(
                        mainSigningAlgSha512Ec,
                        keystorePwd,
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        ECPrivateKeyImpl key = (ECPrivateKeyImpl) keyStore.getKey(KeystoreGenerator.ALIAS, password.toCharArray());
        String curveName = getEcCurveName(key);

        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        Assert.assertEquals("P-384", curveName); //P-384 == secp384r1

        assertCertUserInfos(x500name);
        Assert.assertEquals(mainSigningAlgSha512Ec, certificate.getSigAlgName());
        Assert.assertEquals(keystorePwd, password);
    }

    @Test
    public void createRsaKeystore() throws Exception {
        String keystorePwd = "changeMyPassword!";
        String mainSigningAlgSha512Rsa = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_RSA;

        short selectedKeySize = (short) 4096;
        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createRsaKeystore(
                        mainSigningAlgSha512Rsa,
                        keystorePwd,
                        selectedKeySize,
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        RSAPrivateCrtKeyImpl key = (RSAPrivateCrtKeyImpl) keyStore.getKey(KeystoreGenerator.ALIAS, keystorePwd.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);

        int keySize = key.getModulus().bitLength();

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        assertCertUserInfos(x500name);
        Assert.assertEquals(selectedKeySize, keySize);
        Assert.assertEquals(mainSigningAlgSha512Rsa, certificate.getSigAlgName());
        Assert.assertEquals("RSA", key.getAlgorithm());
        Assert.assertEquals(keystorePwd, password);
    }

    @Test
    public void createRsaWithGeneratedPassword() throws Exception {
        String mainSigningAlgSha512Rsa = KeystoreGenerator.MAIN_SIGNING_ALG_SHA512_RSA;

        short selectedKeySize = (short) 2048;
        KeystoreGenerator.KeystorePasswordHolder keystorePasswordHolder =
                KeystoreGenerator.createRsaKeystore(
                        mainSigningAlgSha512Rsa,
                        selectedKeySize,
                        36,
                        CERT_USER_INFOS);

        KeyStore keyStore = keystorePasswordHolder.getKeyStore();
        String password = keystorePasswordHolder.getPassword();

        RSAPrivateCrtKeyImpl key = (RSAPrivateCrtKeyImpl) keyStore.getKey(KeystoreGenerator.ALIAS, password.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KeystoreGenerator.ALIAS);

        int keySize = key.getModulus().bitLength();

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
        X500Name x500name = new X500Name(issuerX500Principal.getName(X500Principal.CANONICAL));

        assertCertUserInfos(x500name);
        Assert.assertEquals(selectedKeySize, keySize);
        Assert.assertEquals(mainSigningAlgSha512Rsa, certificate.getSigAlgName());
        Assert.assertEquals("RSA", key.getAlgorithm());
        assertThat(password).isNotEmpty().hasSize(64);
    }
}