package com.skillforge.authservice.exception;

public class EmailNotVerifiedException extends RuntimeException {
    public EmailNotVerifiedException(String message)
    {
        super(message);
    }
}
