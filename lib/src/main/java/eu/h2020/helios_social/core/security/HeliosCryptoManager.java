package eu.h2020.helios_social.core.security;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Singleton class to implement HELIOS cryptographic interface {@link HeliosCrypto}
 */
public class HeliosCryptoManager implements HeliosCrypto {

    private static final HeliosCryptoManager ourInstance = new HeliosCryptoManager();
    private static final String TAG = "HeliosCryptoManager";

    /**
     * Get the singleton instance of this Manager.
     *
     * @return {@link HeliosCryptoManager}
     */
    public static HeliosCryptoManager getInstance() {
        return ourInstance;
    }

    private HeliosCryptoManager() {
    }

    @Override
    public SecretKey generateAESKey() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[16];
        secureRandom.nextBytes(seed);
        return new SecretKeySpec(seed, "AES");
    }

    @Override
    public KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "RSA algorithm not found!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] encryptAESKey(PublicKey encryptionRSAKey, SecretKey AESKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionRSAKey);
            return cipher.doFinal(AESKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            Log.d(TAG, "Padding not supported!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            Log.d(TAG, "Bad padding!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            Log.d(TAG, "Illegal block size!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public SecretKey decryptAESKey(PrivateKey decryptionRSAKey, byte[] encryptedAESKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, decryptionRSAKey);
            byte[] decryptedAESKeyBytes = cipher.doFinal(encryptedAESKey);
            return new SecretKeySpec(decryptedAESKeyBytes, 0, decryptedAESKeyBytes.length, "AES");
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            Log.d(TAG, "Padding not supported!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            Log.d(TAG, "Bad padding!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            Log.d(TAG, "Illegal block size!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] encryptBytes(byte[] plaintextBytes, SecretKey AESKey, byte[] iv) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, AESKey, parameterSpec);
            return cipher.doFinal(plaintextBytes);
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            Log.d(TAG, "Padding not supported!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            Log.d(TAG, "Bad padding!");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            Log.d(TAG, "Invalid algorithm parameter!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            Log.d(TAG, "Illegal block size!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] decryptBytes(byte[] cryptotextBytes, SecretKey AESKey, byte[] iv) {
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, AESKey, parameterSpec);
            return cipher.doFinal(cryptotextBytes);
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            Log.d(TAG, "Padding not supported!");
            e.printStackTrace();
        } catch (BadPaddingException e) {
            Log.d(TAG, "Bad padding!");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            Log.d(TAG, "Invalid algorithm parameter!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            Log.d(TAG, "Illegal block size!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[] signBytes(PrivateKey signingRSAKey, byte[] bytesToSign) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(signingRSAKey);
            signature.update(bytesToSign);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (SignatureException e) {
            Log.d(TAG, "Signature exception");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verifyBytes(PublicKey verificationRSAKey, byte[] bytesToSign, byte[] signatureToVerify) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(verificationRSAKey);
            signature.update(bytesToSign);
            return signature.verify(signatureToVerify);
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        } catch (SignatureException e) {
            Log.d(TAG, "Signature exception");
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public byte[] createHMAC(byte[] data, byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(secret, mac.getAlgorithm());
            mac.init(key);
            byte[] calc = mac.doFinal(data);
            return calc;
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "Algorithm not supported!");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            Log.d(TAG, "Invalid key!");
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verifyHMAC(byte[] hmac, byte[] data, byte[] secret) {
        byte[] calc = this.createHMAC(data, secret);
        return Arrays.equals(hmac, calc);
    }
}
