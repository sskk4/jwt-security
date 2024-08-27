package com.seba.jwt_security.service;

import com.seba.jwt_security.email.EmailService;
import com.seba.jwt_security.email.EmailStructure;
import com.seba.jwt_security.email.EmailType;
import com.seba.jwt_security.exception.error.ObjectAlreadyExistException;
import com.seba.jwt_security.exception.error.ResourceNotFoundException;
import com.seba.jwt_security.exception.error.UserFailedAuthentication;
import com.seba.jwt_security.model.RefreshToken;
import com.seba.jwt_security.repository.RefreshTokenRepository;
import com.seba.jwt_security.security.*;
import com.seba.jwt_security.model.Role;
import com.seba.jwt_security.model.User;
import com.seba.jwt_security.repository.UserRepository;
import com.seba.jwt_security.security.request.AuthenticationRequest;
import com.seba.jwt_security.security.request.PasswordChangeRequest;
import com.seba.jwt_security.security.request.RefreshTokenRequest;
import com.seba.jwt_security.security.request.RegisterRequest;
import com.seba.jwt_security.security.response.AuthenticationResponse;
import com.seba.jwt_security.security.response.RefreshTokenResponse;
import com.seba.jwt_security.security.response.RegisterResponse;
import com.seba.jwt_security.util.SecurityUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
    private final EmailService emailService;


    public RegisterResponse register(RegisterRequest request) {
        log.info(TAG + "Create new user");

        if(userRepository.existsByEmail(request.getEmail())) {
            throw new ObjectAlreadyExistException("User with email: {} is already exist");
        }

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .isActive(false)
                .role(Role.USER)
                .build();

        userRepository.save(user);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

        emailService.createMail(
                EmailStructure.builder()
                        .email(user.getEmail())
                        .emailType(EmailType.CONFIRM_EMAIL)
                        .build(),
                emailService.createBody(
                        EmailType.CONFIRM_EMAIL,
                        SecurityUtils.ENDPOINT_ACTIVATE + refreshToken.getToken().toString())
        );

        return RegisterResponse.builder()
                .isActive(request.isActive())
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .role(Role.USER)
                .build();
    }

    public void activate(String token) {
        log.info(TAG + "Activate user");

        RefreshToken refreshToken = refreshTokenService.getTokenByToken(UUID.fromString(token))
                .orElseThrow(() -> new ResourceNotFoundException("Invalid token"));
        User user = refreshToken.getUser();
        user.setActive(true);
        refreshTokenService.deleteRefreshToken(user);
        userRepository.save(user);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info(TAG + "Authenticate");

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
        log.info(TAG + "Logging out user {}", principal.getName());

        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UserFailedAuthentication("Authentication failed"));
        refreshTokenService.deleteRefreshToken(user);
        SecurityContextHolder.clearContext();
        log.info(TAG + "logged out user {}", principal.getName());
    }

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) {
        log.info(TAG + "Refresh access and refresh tokens for user: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserFailedAuthentication("Authentication failed"));

        if(!refreshTokenService.checkIfTokenValid(UUID.fromString(request.getRefreshToken()), user))
                throw new UserFailedAuthentication("Authentication failed");

        refreshTokenService.deleteRefreshToken(user);

        String jwtToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

        return RefreshTokenResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    public void changePassword(PasswordChangeRequest request, CustomPrincipal principal) {
        log.info(TAG + "Change password for user {}", principal.getName());

        User user = userRepository.getUser(principal.getUserId());
        if(!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword()))
            throw new UserFailedAuthentication("Password does not match");
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    private AuthenticationResponse getAuthDto(User user) {
        log.info(TAG + "Get authentication dto for user with email: {}", user.getEmail());

        refreshTokenService.deleteRefreshToken(user);

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.generateRefreshToken(user);

            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken.getToken())
                    .userId(user.getId())
                    .role(user.getRole().name())
                    .build();
    }

    @SneakyThrows
    public void forgotPassword(String email) {
        log.info(TAG + "Forgot password for user {}", email);

        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserFailedAuthentication("user not found"));
        refreshTokenService.deleteRefreshToken(user);
        RefreshToken refreshToken = refreshTokenService.generateRefreshToken(user);

        emailService.createMail(
                EmailStructure.builder()
                        .email(user.getEmail())
                        .emailType(EmailType.FORGOT_PASSWORD)
                        .build(),
                emailService.createBody(
                        EmailType.FORGOT_PASSWORD,
                        SecurityUtils.ENDPOINT_RECOVERY + refreshToken.getToken().toString())
        );
    }

    @SneakyThrows
    public void recoveryPassword(String token, String password) {
        log.info(TAG + "Recovery password for user with token: {}", token);

        RefreshToken tokenFromDB = refreshTokenService.getTokenByToken(UUID.fromString(token))
                .orElseThrow(() -> new UserFailedAuthentication("Authentication failed"));

        var user = userRepository.findById(tokenFromDB.getUser().getId())
                .orElseThrow(() -> new UserFailedAuthentication("user not found"));

        refreshTokenService.deleteRefreshToken(user);

        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);

        emailService.createMail(
                EmailStructure.builder()
                        .email(user.getEmail())
                        .emailType(EmailType.PASSWORD_WAS_CHANGED)
                        .build(),
                emailService.createBody(
                        EmailType.PASSWORD_WAS_CHANGED));
    }

    public void updateUserRole(Long userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserFailedAuthentication("User not found"));
        user.setRole(role);
        userRepository.save(user);
    }
}
