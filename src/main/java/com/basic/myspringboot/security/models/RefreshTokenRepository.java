package com.basic.myspringboot.security.models;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    //제시된 refresh 토큰으로 조회
    Optional<RefreshToken> findByToken(String token);
}
