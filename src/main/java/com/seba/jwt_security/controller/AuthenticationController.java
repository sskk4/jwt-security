package com.seba.jwt_security.controller;

import com.seba.jwt_security.security.*;
import com.seba.jwt_security.service.AuthenticationService;
import com.seba.jwt_security.util.SecurityHolder;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@CrossOrigin
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final String TAG = "AUTHENTICATION CONTROLLER - ";

    private final AuthenticationService authenticationService;

    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register user and get response")
    @PostMapping("/register")
    public RegisterResponse login(
        @RequestBody RegisterRequest request) {
        log.info(TAG + "Register");
        return authenticationService.register(request);
    }

    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Login user and get response")
    @PostMapping("/authenticate")
    public AuthenticationResponse login(
            @RequestBody AuthenticationRequest request) {
        log.info(TAG + "authenticate");
        return authenticationService.authenticate(request);
    }

    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "logout user, inactive refresh token")
    @GetMapping("/logout")
    public void logout() {
        log.info(TAG + "Logout");
        authenticationService.logout(SecurityHolder.getPrincipal());
    }

    @ResponseStatus(HttpStatus.OK)
    @Operation(summary = "Refresh token and get response")
    @PostMapping("/refresh")
    public RefreshTokenResponse refreshToken(
            @RequestBody RefreshTokenRequest request) {
        log.info(TAG + "refresh");
        return authenticationService.refreshToken(request);
    }
}
