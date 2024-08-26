package com.seba.jwt_security.repository;

import com.seba.jwt_security.model.RefreshToken;
import com.seba.jwt_security.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUserAndToken(User user, UUID token);

    Optional<RefreshToken> findByToken(UUID refreshToken);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.user.id = :userId")
    void deleteAllByUserId(@Param("userId") Long userId);
}
