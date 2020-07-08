package eu.h2020.helios_social.core.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * Interface class for HELIOS cryptographic operations
 */
public interface HeliosCrypto {

    /**
     * Generates a random AES key.
     * @return new AES key {@link SecretKey}
     */
    SecretKey generateAESKey();

    /**
     * Generates a random RSA 2048 bit public key - private key pair for encryption or signing.
     * @return new RSA key pair {@link KeyPair}
     */
    KeyPair generateRSAKeyPair();

    /**
     * Encrypts an AES key using a RSA encryption key. Used mode is ECB and OAEPWithSHA1AndMGF1Padding.
     * (It is faster to encrypt a message using AES and then encrypt the AES key with RSA than to encrypt the whole message with RSA.)
     * @param encryptionRSAKey The RSA key that is used for encryption {@link PublicKey}
     * @param AESKey The key that will be encrypted {@link SecretKey}
     * @return The AES key in encrypted form as byte array
     */
    byte[] encryptAESKey(PublicKey encryptionRSAKey, SecretKey AESKey);

    /**
     * Decrypts an encrypted AES key using a RSA decryption key.
     * @param decryptionRSAKey The RSA key that is used for decryption {@link PrivateKey}
     * @param encryptedAESKey The AES key in encrypted form as byte array
     * @return The decrypted AES key {@link SecretKey}
     */
    SecretKey decryptAESKey(PrivateKey decryptionRSAKey, byte[] encryptedAESKey);

    /**
     * Encrypts an array of bytes using AES in Galois Counter Mode and with NoPadding. The authentication tag length is 128 bits.
     * The value of iv must be different for every encryption so the method chooses one randomly.
     * The decryption is impossible without the correct initial value, thus the value of iv must be saved afterwards.
     * The iv can then be stored or sent with the plaintext.
     * @param plaintextBytes The plaintext
     * @param AESKey The AES key that is used for encryption {@link SecretKey}
     * @param iv The random initial value (12 bytes) that the method generates for GCM
     * @return The cryptotext as byte array
     */
    byte[] encryptBytes(byte[] plaintextBytes, SecretKey AESKey, byte[] iv);

    /**
     * Decrypts a cryptotext using AES in Galois Counter Mode and with NoPadding. Returns null if the cryptotext is not generated correctly.
     * @param cryptotextBytes The cryptotext
     * @param AESKey The AES key that is used for decryption {@link SecretKey}
     * @param iv The initial value for GCM. Must be the same that was used in encryption, otherwise decryption fails.
     * @return The plaintext as byte array
     */
    byte[] decryptBytes(byte[] cryptotextBytes, SecretKey AESKey, byte[] iv);

    /**
     * Signs a byte array using RSA and SHA 256.
     * @param signingRSAKey The RSA key that is used for signing {@link PrivateKey}
     * @param bytesToSign The byte array that is to be signed
     * @return The signature as byte array
     */
    byte[] signBytes(PrivateKey signingRSAKey, byte[] bytesToSign);

    /**
     * Checks if a signature is valid, that is, generated with the private RSA key corresponding to the public key.
     * @param verificationRSAKey The public RSA key that is used for verification {@link PublicKey}
     * @param bytesToSign The byte array that was signed
     * @param signatureToVerify The signature that is to be verified
     * @return True if the signature was valid, false otherwise.
     */
    boolean verifyBytes(PublicKey verificationRSAKey, byte[] bytesToSign, byte[] signatureToVerify);

    /**
     * Calculates the HMAC (message authentication code) for a byte array using SHA 256.
     * @param data The input bytes
     * @param secret The secret key
     * @return The HMAC of length 256 bits as byte array
     */
    byte[] createHMAC(byte[] data, byte[] secret);

    /**
     * Checks if a HMAC value is valid.
     * @param hmac The 256 bit HMAC that is to be checked
     * @param data The input that was used to generate the HMAC
     * @param secret The secret key that was used to generate the HMAC
     * @return True if the HMAC was valid, false otherwise.
     */
    boolean verifyHMAC(byte[] hmac, byte[] data, byte[] secret);
}
