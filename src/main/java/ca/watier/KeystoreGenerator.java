/*
 *    Copyright 2014 - 2018 Yannick Watier
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;

import static java.time.ZoneOffset.UTC;

/**
 * Created by yannick on 6/5/2017.
 */
public final class KeystoreGenerator {
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    public static final String PRNG = "SHA1PRNG";
    public static final String ALIAS = "alias";
    public static final String KEYPAIR_SIGNING_ALG_EC = "ECDSA";
    public static final String KEYPAIR_SIGNING_ALG_RSA = "RSA";
    public static final String MAIN_SIGNING_ALG_SHA512_EC = "SHA512withECDSA";
    public static final String MAIN_SIGNING_ALG_SHA512_RSA = "SHA512withRSA";
    public static final String EC_CURVE = "secp384r1";
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(KeystoreGenerator.class);
    private static final short SERIAL_BYTES_LENGTH = 1024;
    private static SecureRandom secureRandom = null;

    static {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e2) {
            secureRandom = new SecureRandom();
        }
    }

    private KeystoreGenerator() {
    }

    /**
     * Create a keystore with ECDSA and a random password (64 characters)
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param curveName     - The EC curve name
     * @param keystorePwd   - The password to use with key the store
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createEcKeystore(@NotNull String signingAlg,
                                                                   @NotNull String curveName,
                                                                   @NotNull String keystorePwd,
                                                                   int expiryNbMonth,
                                                                   @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateEcdsaKeyPair(curveName), keystorePwd, expiryNbMonth, certUserInfo);
    }

    private static @NotNull KeystorePasswordHolder createKeystore(@NotNull String signingAlg,
                                                                  @NotNull KeyPair pair,
                                                                  @Nullable String keystorePwd,
                                                                  int expiryNbMonth,
                                                                  @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {

        String password = (keystorePwd == null ? nextPassword() : keystorePwd);
        KeyStore keyStore;
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        for (Map.Entry<ASN1ObjectIdentifier, String> bcStyleStringEntry : certUserInfo.entrySet()) {
            nameBuilder.addRDN(bcStyleStringEntry.getKey(), bcStyleStringEntry.getValue());
        }

        X500Name xName = nameBuilder.build();
        BigInteger serialNumber = new BigInteger(SERIAL_BYTES_LENGTH, secureRandom);

        LocalDateTime startDate = LocalDateTime.now();
        LocalDateTime endDate = startDate.plusMonths(expiryNbMonth);
        SubjectPublicKeyInfo infos = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(xName, serialNumber, Date.from(startDate.toInstant(UTC)), Date.from(endDate.toInstant(UTC)), xName, infos);
        try {
            certBuilder.addExtension(Extension.subjectAlternativeName,
                    false, new GeneralNames(
                            new GeneralName(GeneralName.iPAddress, "127.0.0.1")));
        } catch (CertIOException e) {
            e.printStackTrace();
        }

        ContentSigner signer = null;
        try {
            signer = new JcaContentSignerBuilder(signingAlg).build(privateKey);
        } catch (OperatorCreationException e1) {
            LOGGER.error(e1.toString(), e1);
            System.exit(-1);
        }

        X509CertificateHolder certHolder = certBuilder.build(signer);

        try {
            X509Certificate cert = (new JcaX509CertificateConverter()).getCertificate(certHolder);

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);

            keyStore.setKeyEntry(ALIAS, pair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
        } catch (final Exception e) {
            throw new IllegalStateException("Errors during assembling root CA.", e);
        }


        return new KeystorePasswordHolder(password, keyStore);
    }

    private static @NotNull KeyPair generateEcdsaKeyPair(@NotNull String curveName) {
        KeyPairGenerator keyGenerator = null;

        try {
            keyGenerator = KeyPairGenerator.getInstance(KEYPAIR_SIGNING_ALG_EC, PROVIDER_NAME);
            keyGenerator.initialize(ECNamedCurveTable.getParameterSpec(curveName), secureRandom);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            LOGGER.error(e.toString(), e);
        }

        if (keyGenerator == null) {
            LOGGER.error("Unable to generate a KeyPair");
            System.exit(-1);
        }

        return keyGenerator.generateKeyPair();
    }

    /**
     * Gives a 64 characters password (5 bits * 64 = 320) <br>
     * Thanks to erickson from StackOverflow (https://stackoverflow.com/a/41156)
     *
     * @return
     */
    private static @NotNull String nextPassword() {
        return new BigInteger(320, secureRandom).toString(32);
    }

    /**
     * Create a keystore with ECDSA and the default curve (secp384r1, supported by most browsers)
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA, SHA512withECDSA, etc)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createEcWithDefaultCurveKeystoreAndPassword(@NotNull String signingAlg,
                                                                                              int expiryNbMonth,
                                                                                              @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateEcdsaKeyPair(EC_CURVE), null, expiryNbMonth, certUserInfo);
    }

    /**
     * Create a keystore with ECDSA and the default curve (secp384r1, supported by most browsers)
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA, SHA512withECDSA, etc)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param keystorePwd   - The password to use with key the store
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createEcWithDefaultCurveKeystore(@NotNull String signingAlg,
                                                                                   @NotNull String keystorePwd,
                                                                                   int expiryNbMonth,
                                                                                   @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateEcdsaKeyPair(EC_CURVE), keystorePwd, expiryNbMonth, certUserInfo);
    }

    /**
     * Create a keystore with ECDSA and a random password (64 characters)
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA, SHA512withECDSA, etc)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param curveName     - The EC curve name <br> You can see a list of supported curves at https://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createEcKeystore(@NotNull String signingAlg,
                                                                   @NotNull String curveName,
                                                                   int expiryNbMonth,
                                                                   @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateEcdsaKeyPair(curveName), null, expiryNbMonth, certUserInfo);
    }

    /**
     * Create a keystore with RSA and a random password (64 characters)
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA, SHA512withECDSA, etc)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param keySize       - The RSA key size (2048, 4096, etc)
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createRsaKeystore(@NotNull String signingAlg,
                                                                    short keySize,
                                                                    int expiryNbMonth,
                                                                    @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateRsaKeyPair(keySize), null, expiryNbMonth, certUserInfo);
    }

    private static @NotNull KeyPair generateRsaKeyPair(short keySize) {
        KeyPairGenerator keyGenerator = null;

        try {

            keyGenerator = KeyPairGenerator.getInstance(KEYPAIR_SIGNING_ALG_RSA, PROVIDER_NAME);
            keyGenerator.initialize(keySize, secureRandom);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            LOGGER.error(e.toString(), e);
        }

        if (keyGenerator == null) {
            LOGGER.error("Unable to generate a KeyPair");
            System.exit(-1);
        }

        return keyGenerator.generateKeyPair();
    }

    /**
     * Create a keystore with RSA and a specified keystore password
     *
     * @param signingAlg    - The signature algorithm (Example: SHA512WithRSA, SHA512withECDSA, etc)<br>
     *                      You can find a list of supported signature algorithms at https://bouncycastle.org/specifications.html, section "Signature Algorithms"
     * @param keystorePwd   - The password to use with key the store
     * @param keySize       - The RSA key size (2048, 4096, etc)
     * @param expiryNbMonth - The number of month before the expiration of the certificate
     * @param certUserInfo  - The user settings of the certificate (BCStyle.C, BCStyle.O, BCStyle.CN, etc)
     * @return
     */
    public static @NotNull KeystorePasswordHolder createRsaKeystore(@NotNull String signingAlg,
                                                                    @NotNull String keystorePwd,
                                                                    short keySize,
                                                                    int expiryNbMonth,
                                                                    @NotNull Map<ASN1ObjectIdentifier, String> certUserInfo) {
        return createKeystore(signingAlg, generateRsaKeyPair(keySize), keystorePwd, expiryNbMonth, certUserInfo);
    }

    public static class KeystorePasswordHolder {
        private final String password;
        private final KeyStore keyStore;

        public KeystorePasswordHolder(@NotNull String password,
                                      @NotNull KeyStore keyStore) {
            this.password = password;
            this.keyStore = keyStore;
        }

        public String getPassword() {
            return password;
        }

        public KeyStore getKeyStore() {
            return keyStore;
        }
    }
}
