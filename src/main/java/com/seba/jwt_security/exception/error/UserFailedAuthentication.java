package com.seba.jwt_security.exception.error;

public class UserFailedAuthentication extends RuntimeException {

    public UserFailedAuthentication(final String message) {
        super(message);
    }
}
