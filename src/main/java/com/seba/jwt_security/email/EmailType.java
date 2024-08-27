package com.seba.jwt_security.email;

public enum EmailType {

    CONFIRM_EMAIL("Email confirmation"),
    ANNOUNCEMENT("Announcement"),
    PASSWORD_WAS_CHANGED("Password was changed"),
    FORGOT_PASSWORD("Forgot password");

    private final String subject;

    EmailType(String subject) {
        this.subject = subject;
    }

    public String getSubject() {
        return subject;
    }
}

