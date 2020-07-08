package eu.h2020.helios_social.core.security;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;

/**
 * Interface class for HELIOS key storage operations
 */
public interface HeliosKeyStore {

    /**
     * Stores an AES key to the key store. The key is issued a name and a password that are required when retrieving the key.
     * @param aesKey The key to be stored {@link SecretKey}
     * @param alias The name assigned for the key
     * @param passPhrase The password for the key
     * @throws HeliosKeyStoreException if the operation fails.
     */
    void storeSecretKey(SecretKey aesKey, String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Retrieves an AES key from the key store.
     * @param alias The name of the key
     * @param passPhrase The password of the key
     * @return The AES key {@link SecretKey}
     * @throws HeliosKeyStoreException if the operation fails.
     */
    SecretKey retrieveSecretKey(String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Stores a private RSA key (and a self signed certificate) to the key store. The key is issued a name and a password that are required when retrieving the key.
     * @param rsaKey The RSA key that is to be stored {@link PrivateKey}
     * @param alias The name assigned for the key
     * @param passPhrase The password for the key
     * @throws HeliosKeyStoreException if the operation fails.
     */
    void storePrivateKey(PrivateKey rsaKey, String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Retrieves a private RSA key from the key store.
     * @param alias The name of the key
     * @param passPhrase The password of the key
     * @return The private RSA key {@link PrivateKey}
     * @throws HeliosKeyStoreException if the operation fails.
     */
    PrivateKey retrievePrivateKey(String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Stores a certificate to the key store. The certificate is issued a name and a password that are required when retrieving the certificate.
     * @param cert The certificate to be stored {@link Certificate}
     * @param alias The name assigned for the certificate
     * @param passPhrase The password for the certificate
     * @throws HeliosKeyStoreException if the operation fails.
     */
    void storeCertificate(Certificate cert, String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Retrieves a certificate from the key store.
     * @param alias The name of the certificate
     * @param passPhrase The password of the certificate
     * @return The certificate {@link Certificate}
     * @throws HeliosKeyStoreException if the operation fails.
     */
    Certificate retrieveCertificate(String alias, String passPhrase) throws HeliosKeyStoreException;

    /**
     * Get the aliases (names) of all items in the key store.
     * @return The aliases of all items in the key store
     * @throws HeliosKeyStoreException if the operation fails.
     */
    String[] getAliases() throws HeliosKeyStoreException;

    /**
     * Delete an item in the key store.
     * @param alias The name of the item to be deleted from the key store
     * @throws HeliosKeyStoreException
     */
    void deleteAlias(String alias) throws HeliosKeyStoreException;
}
