package com.basic.myspringboot.security.models;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    //제시된 refresh 토큰의 해시로 조회
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    //[재사용 탐지 대응] 탈취 의심 시 해당 사용자의 모든 refresh 토큰을 일괄 폐기(삭제)
    void deleteAllByUserUuid(String userUuid);
}
