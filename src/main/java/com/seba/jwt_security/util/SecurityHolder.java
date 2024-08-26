package com.seba.jwt_security.util;

import com.seba.jwt_security.security.CustomPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityHolder {

    public static CustomPrincipal getPrincipal() {
        return ((CustomPrincipal)
                (SecurityContextHolder.getContext().getAuthentication())
                        .getPrincipal());
    }
}
