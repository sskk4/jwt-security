package com.seba.jwt_security.repository;

import com.seba.jwt_security.model.RefreshToken;
import com.seba.jwt_security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUserAndToken(User user, UUID token);

    Optional<RefreshToken> findByToken(UUID refreshToken);

    @Query("SELECT r " +
            "FROM RefreshToken r " +
            "WHERE r.user.id = :userId")
    RefreshToken findByUser(@Param("userId") Long userId);

    void deleteAllByUser(User user);
}
