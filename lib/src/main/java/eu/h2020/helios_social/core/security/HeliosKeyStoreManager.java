package eu.h2020.helios_social.core.security;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

import javax.crypto.SecretKey;

/**
 * HELIOS key storage class implementation for {@link HeliosKeyStore}.
 */
public class HeliosKeyStoreManager implements HeliosKeyStore {

    private static final String TAG = "HeliosKeyStoreManager";
    private static final String KEYSTORE_FILENAME = "helios.keystore";
    private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
    private Context context;

    /**
     * Constructor.
     *
     * @param context {@link Context} to be used in operations.
     */
    public HeliosKeyStoreManager(Context context) {
        this.context = context;
    }

    private KeyStore createKeyStore() throws HeliosKeyStoreException {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, KEYSTORE_PASSWORD);
        } catch (IOException e) {
            throw new HeliosKeyStoreException("Unable to create empty keyStore", e);
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (CertificateException e) {
            throw new HeliosKeyStoreException("Certificate exception", e);
        } catch (NoSuchAlgorithmException e) {
            throw new HeliosKeyStoreException("Unsupported algorithm", e);
        }
        return ks;
    }

    private KeyStore loadKeyStore(KeyStore ks) throws HeliosKeyStoreException {
        try (FileInputStream fis = context.openFileInput(KEYSTORE_FILENAME)) {
            ks.load(fis, KEYSTORE_PASSWORD);
        } catch (FileNotFoundException e) {
            ks = null;
        } catch (IOException e) {
            ks = null;
        } catch (GeneralSecurityException e) {
            ks = null;
        }
        if (ks == null) {
            ks = createKeyStore();
        }
        storeKeyStore(ks);
        return ks;
    }

    private synchronized void storeKeyStore(KeyStore ks) {
        try (FileOutputStream fos = context.openFileOutput(KEYSTORE_FILENAME, Context.MODE_PRIVATE) ){
            ks.store(fos, KEYSTORE_PASSWORD);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private KeyStore getHeliosKeyStore() throws GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        return loadKeyStore(ks);
    }

    private PublicKey getRSAPublicKey(PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateKey)) {
            Log.e(TAG, "Private key is not RSA private key");
            return null;
        }
        PublicKey publicKey = null;
        BigInteger modulus = ((RSAKey)privateKey).getModulus();
        BigInteger publicExponent = new BigInteger("65537");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(publicKeySpec);
            if (publicKey != null) {
                Log.d(TAG, "Public key extracted from the private key");
                Log.d(TAG, "Algorithm: " + publicKey.getAlgorithm());
                Log.d(TAG, "Format: " + publicKey.getFormat());
            } else {
                Log.e(TAG, "Public key extract failed");
            }
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "No such algorithm");
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "Invalid key spec");
        }
        return publicKey;
    }

    @Override
    public void storeSecretKey(SecretKey aesKey, String alias, String passPhrase)
            throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(aesKey);
            ks.setEntry(alias, skEntry, protParam);
            storeKeyStore(ks);
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

    @Override
    public SecretKey retrieveSecretKey(String alias, String passPhrase) throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, protParam);
            return (skEntry != null) ? skEntry.getSecretKey() : null;
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (UnrecoverableEntryException e) {
            throw new HeliosKeyStoreException("Unrecoverable entry", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security error", e);
        }
    }

    @Override
    public void storePrivateKey(PrivateKey rsaKey, String alias, String passPhrase)
            throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            PublicKey publicKey = getRSAPublicKey(rsaKey);
            Log.d(TAG, "Public key extracted");
            Certificate cert = new SelfSignedCert().build(rsaKey, publicKey);
            Log.d(TAG, "Certificate generated");
            KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(rsaKey, new Certificate[]{cert});
            //Certificate[] certChain = new Certificate[0];
            //KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(rsaKey, certChain);
            Log.d(TAG, "Private key storage entry created");
            ks.setEntry(alias, pkEntry, protParam);
            Log.d(TAG, "Private key entry set");
            storeKeyStore(ks);
            Log.d(TAG, "Private key entry stored");
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

    @Override
    public PrivateKey retrievePrivateKey(String alias, String passPhrase)
            throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
            return (pkEntry != null) ? pkEntry.getPrivateKey() : null;
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        }  catch (UnrecoverableEntryException e) {
            throw new HeliosKeyStoreException("Unrecoverable entry", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

    @Override
    public void storeCertificate(Certificate cert, String alias, String passPhrase)
            throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            KeyStore.TrustedCertificateEntry certEntry = new KeyStore.TrustedCertificateEntry(cert);
            ks.setEntry(alias, certEntry, protParam);
            storeKeyStore(ks);
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

    @Override
    public Certificate retrieveCertificate(String alias, String passPhrase)
            throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            KeyStore.ProtectionParameter protParam;
            protParam = new KeyStore.PasswordProtection(passPhrase.toCharArray());
            KeyStore.TrustedCertificateEntry certEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry(alias, protParam);
            return (certEntry != null) ? certEntry.getTrustedCertificate() : null;
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (UnrecoverableEntryException e) {
            throw new HeliosKeyStoreException("Unrecoverable entry", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security error", e);
        }
    }

    @Override
    public String[] getAliases() throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            final Enumeration<String> enumeration = ks.aliases();
            ArrayList<String> arrayList = Collections.list(enumeration);
            return arrayList.toArray(new String[arrayList.size()]);
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

    @Override
    public void deleteAlias(String alias) throws HeliosKeyStoreException {
        try {
            KeyStore ks = getHeliosKeyStore();
            ks.deleteEntry(alias);
            storeKeyStore(ks);
        } catch (KeyStoreException e) {
            throw new HeliosKeyStoreException("Unable to get keyStore", e);
        } catch (GeneralSecurityException e) {
            throw new HeliosKeyStoreException("General security exception", e);
        }
    }

}
