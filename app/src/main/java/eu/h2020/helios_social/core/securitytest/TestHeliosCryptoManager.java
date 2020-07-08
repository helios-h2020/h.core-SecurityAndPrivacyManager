package eu.h2020.helios_social.core.securitytest;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import android.content.Context;
import android.util.Log;
import android.widget.TextView;

import javax.crypto.SecretKey;

import eu.h2020.helios_social.core.security.HeliosCryptoManager;
import eu.h2020.helios_social.core.security.HeliosKeyStoreManager;
import eu.h2020.helios_social.core.security.SelfSignedCert;

public class TestHeliosCryptoManager {
    private static final String TAG = "HELIOS";
    private Context context;
    private TextView textView;

    public TestHeliosCryptoManager(Context context, TextView textView) {
        this.context = context;
        this.textView = textView;
    }

    public void run() {
        String hexstr;
        logMessage("testSec-----");
        HeliosCryptoManager manager = HeliosCryptoManager.getInstance();
        // Generating RSA keys sign the message
        KeyPair senderRSASignPair = manager.generateRSAKeyPair();
        // Generating RSA keys to encrypt the AES keys
        KeyPair receiverRSAEncPair = manager.generateRSAKeyPair();
        // Generating the AES key to encrypt the message
        SecretKey messageEncryptionKey = manager.generateAESKey();
        // Print AES key
        byte[] keydump = messageEncryptionKey.getEncoded();
        hexstr = buffer2Hex(keydump);
        logMessage("AES key(1): " + hexstr);

        // Test encrypting AES key
        byte[] encryptedAESKey = manager.encryptAESKey(receiverRSAEncPair.getPublic(), messageEncryptionKey);
        // Test decrypting AES key
        messageEncryptionKey = manager.decryptAESKey(receiverRSAEncPair.getPrivate(), encryptedAESKey);
        // Print AES key again to check if decryption was successful
        keydump = messageEncryptionKey.getEncoded();
        hexstr = buffer2Hex(keydump);
        logMessage("AES key(2): " + hexstr);

        String originalString = "Here is the string we will encrypt and decrypt later";

        // Test encrypting the message using AES
        byte[] iv = new byte[12];
        byte[] originalByteArray;
        try {
            originalByteArray = originalString.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            logMessage("UTF-8 encoding not supported - stop!");
            return;
        }
        byte[] encryptedByteArray = manager.encryptBytes(originalByteArray, messageEncryptionKey, iv);

        // Test decrypting the message using AES
        byte[] decryptedByteArray = manager.decryptBytes(encryptedByteArray, messageEncryptionKey, iv);
        String decryptedString = new String(decryptedByteArray);

        // Print plaintext, cryptotext and decrypted text to check if decryption was successful
        logMessage("ORIGINAL :" + originalString);
        hexstr = buffer2Hex(encryptedByteArray);
        logMessage("ENCRYPTED:" + hexstr);
        logMessage("DECRYPTED:" + decryptedString);

        // Test signing the encrypted message
        byte[] generatedSignature = manager.signBytes(senderRSASignPair.getPrivate(), encryptedByteArray);
        // Test verifying the signature
        if (manager.verifyBytes(senderRSASignPair.getPublic(), encryptedByteArray, generatedSignature)) {
            logMessage("Sign OK");
        }

        try {
            HeliosKeyStoreManager keyManager = new HeliosKeyStoreManager(context);
            keyManager.storeSecretKey(messageEncryptionKey, new String("MEK"), new String("passphrase"));
            logMessage("Key stored");

            PublicKey publicKey = senderRSASignPair.getPublic();
            PrivateKey privateKey = senderRSASignPair.getPrivate();
            X509Certificate certGenerated = new SelfSignedCert().build(privateKey, publicKey);
            keyManager.storeCertificate(certGenerated, new String("CERT"), new String("passphrase"));
            logMessage("Cert stored");
            logMessage("Certificate:\n" + certGenerated.toString());

            String[] aliases = keyManager.getAliases();
            for (int i = 0; i < aliases.length; i++) {
                logMessage("Alias: " + aliases[i]);
            }
        } catch (Exception e) {
            logMessage("Caught exception");
            e.printStackTrace();
        }
    }

    private String buffer2Hex(byte[] buffer) {
        String output = "";
        for (int i = 0; i < buffer.length; i++) {
            if (i > 0 && i % 16 == 0) {
                output += "\n";
            }
            output += String.format("%02X", buffer[i]);
        }
        return output;
    }

    private void logMessage(String msg) {
        Log.d(TAG, msg);
        textView.append(msg + "\n");
    }
}
