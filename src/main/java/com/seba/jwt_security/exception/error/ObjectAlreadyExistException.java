package com.seba.jwt_security.exception.error;

public class ObjectAlreadyExistException extends RuntimeException{

    public ObjectAlreadyExistException(String message) {
        super(message);
    }
}
