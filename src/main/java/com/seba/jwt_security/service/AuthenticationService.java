package com.seba.jwt_security.service;

import com.seba.jwt_security.exception.error.UserFailedAuthentication;
import com.seba.jwt_security.model.RefreshToken;
import com.seba.jwt_security.repository.RefreshTokenRepository;
import com.seba.jwt_security.security.*;
import com.seba.jwt_security.model.Role;
import com.seba.jwt_security.model.User;
import com.seba.jwt_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final String TAG = "AUTHENTICATION SERVICE - ";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public RegisterResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        return RegisterResponse.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        return getAuthDto(user);
    }

    public void logout(CustomPrincipal principal) {
        log.info("Logging out user {}", principal.getName());
        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UserFailedAuthentication("Authentication failed"));
        refreshTokenService.deleteRefreshToken(user);
        SecurityContextHolder.clearContext();
    }

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) {
        log.info(TAG + "Refresh access and refresh tokens for user: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserFailedAuthentication("Authentication failed"));

        if(!refreshTokenService.checkIfTokenValid(UUID.fromString(request.getRefreshToken()), user))
                throw new UserFailedAuthentication("Authentication failed");

        RefreshToken rf = refreshTokenService.getTokenByToken(UUID.fromString(request.getRefreshToken())).get();
        refreshTokenRepository.delete(rf);

        // error was here haha
        /*
        refreshTokenService.deleteRefreshToken(user);
        */

        String jwtToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

        return RefreshTokenResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    private AuthenticationResponse getAuthDto(User user) {
            log.info(TAG + "Get authentication dto for user with email: {}", user.getEmail());

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.generateRefreshToken(user);

            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken.getToken())
                    .userId(user.getId())
                    .roles(List.of(user.getRole().name()))
                    .build();
    }
}
