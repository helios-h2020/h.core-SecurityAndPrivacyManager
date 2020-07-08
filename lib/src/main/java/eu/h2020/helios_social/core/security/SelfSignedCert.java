package eu.h2020.helios_social.core.security;

import android.util.Log;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Random;

import org.spongycastle.cert.X509v1CertificateBuilder;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;

/**
 * Build self signed certificate using tools from Spongy Castle
 * cryptographic library. Standard Android APIs do not contain
 * certificate creation functionality. This code is using Spongy
 * Castle (from  https://rtyley.github.io/spongycastle/). The
 * self signing code itself is based on Yaniv Bouhadana's example
 * that is available here:
 * https://medium.com/@bouhady/self-sign-certificate-creation-using-spongy-castle-for-android-app-61f1545dd63
 */
public class SelfSignedCert {
    private static final String TAG = "SelfSignedCert";

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    /**
     * Build a X509Certificate certificate with provided keys.
     *
     * @param privateKey used {@link PrivateKey}.
     * @param publicKey used {@link PublicKey}.
     * @return {@link java.security.cert.X509Certificate}
     */
    public java.security.cert.X509Certificate build(PrivateKey privateKey, PublicKey publicKey) {
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + 10 * 365 * 24 * 60 * 60 * 1000);

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.O,"H2020");
        nameBuilder.addRDN(BCStyle.OU,"HELIOS");
        nameBuilder.addRDN(BCStyle.L,"EU");

        X500Name x500Name = nameBuilder.build();
        Random random = new Random();

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(x500Name,
                BigInteger.valueOf(random.nextLong()), startDate, endDate ,x500Name,
                subjectPublicKeyInfo);
        ContentSigner sigGen = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("SC").build(privateKey);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
        X509CertificateHolder x509CertificateHolder = v1CertGen.build(sigGen);

        java.security.cert.X509Certificate selfSignedCert = null;
        try {
            selfSignedCert = new JcaX509CertificateConverter().setProvider("SC").getCertificate(x509CertificateHolder);
        } catch (CertificateException e) {
            Log.e(TAG, "Certificate conversion failed");
        }
        return selfSignedCert;
    }
}
