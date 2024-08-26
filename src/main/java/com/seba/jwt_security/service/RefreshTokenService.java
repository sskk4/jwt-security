package com.seba.jwt_security.service;

import com.seba.jwt_security.exception.error.ResourceNotFoundException;
import com.seba.jwt_security.exception.error.UserFailedAuthentication;
import com.seba.jwt_security.model.RefreshToken;
import com.seba.jwt_security.model.User;
import com.seba.jwt_security.repository.RefreshTokenRepository;
import com.seba.jwt_security.util.DateService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final String TAG = "REFRESH TOKEN SERVICE - ";

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken getRefreshTokenById(Long tokenId){
        log.info(TAG + "Get refresh token by id: {}", tokenId);
        return refreshTokenRepository.findById(tokenId).orElseThrow(
                () -> new ResourceNotFoundException("refresh token not found"));
    }

    public Optional<RefreshToken> getTokenByToken(UUID refreshToken){
        log.info(TAG + "Get refresh token by token: {}", refreshToken);
        return refreshTokenRepository.findByToken(refreshToken);
    }

    public boolean checkIfTokenValid(UUID refreshToken, User user) {
        log.info(TAG + "Check if token is valid and belongs to user: {}", user.getEmail());
        RefreshToken token = refreshTokenRepository.findByUserAndToken(user, refreshToken)
                .orElseThrow(() -> new UserFailedAuthentication("User authentication failed"));
        return token.getExpired() != null && token.getExpired().isAfter(LocalDateTime.now());
    }

    public RefreshToken generateRefreshToken(User user){

        log.info(TAG + "Create refresh token for user with email: {}", user.getEmail());

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID());
        refreshToken.setCreated(DateService.getDateNow());
        refreshToken.setExpired(DateService.addDaysToDate(DateService.getDateNow(), 1));
        return refreshTokenRepository.save(refreshToken);
    }

    public void deleteRefreshToken(User user){
        log.info(TAG + "Delete refresh token for user with email: {}", user.getEmail());

        RefreshToken refreshToken = refreshTokenRepository.findByUser(user.getId());
        refreshTokenRepository.deleteById(refreshToken.getId());
        log.info(TAG + "Refresh tokens deleted");
    }

}
