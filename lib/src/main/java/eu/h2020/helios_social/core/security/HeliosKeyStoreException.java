package eu.h2020.helios_social.core.security;

import java.security.GeneralSecurityException;

/**
 * Exception that can be thrown from HELIOS key storage methods.
 */
public class HeliosKeyStoreException extends GeneralSecurityException {

    private String msg;

    HeliosKeyStoreException(String msg, Exception e) {
        this.msg = msg;
        if (e != null) {
            e.printStackTrace();
        }
    }
}


