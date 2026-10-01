package com.basic.myspringboot.security.service;

import com.basic.myspringboot.security.models.RefreshToken;
import com.basic.myspringboot.security.models.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * [JWT 2단계] Refresh 토큰 발급·회전·폐기.
 *
 *  - issue  : 로그인 시 새 refresh 토큰을 만들어 DB 에 저장
 *  - rotate : refresh 로 새 access 를 받을 때, 기존 refresh 를 폐기하고 새 refresh 로 교체(1회용·회전)
 *  - revoke : 로그아웃 시 refresh 토큰 삭제(폐기)
 *
 * 회전(rotation) 덕분에, 한 번 쓴 refresh 는 즉시 무효가 되어 탈취·재사용에 강해진다.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    @Value("${jwt.refresh-expire-seconds}")
    private long refreshExpireSeconds;

    /** 로그인 시: 사용자(uuid)에 대한 새 refresh 토큰 발급·저장 */
    @Transactional
    public RefreshToken issue(String userUuid) {
        RefreshToken rt = new RefreshToken();
        rt.setToken(newOpaqueToken());
        rt.setUserUuid(userUuid);
        rt.setExpiresAt(Instant.now().plusSeconds(refreshExpireSeconds));
        return repository.save(rt);
    }

    /**
     * 갱신 시: 제시된 refresh 가 유효하면 폐기하고 새 refresh 로 교체(회전).
     * 유효하지 않거나 만료면 401(BadCredentialsException) 로 처리된다.
     */
    @Transactional
    public RefreshToken rotate(String presentedToken) {
        RefreshToken rt = repository.findByToken(presentedToken)
                .orElseThrow(() -> new BadCredentialsException("유효하지 않은 refresh 토큰입니다"));

        if (rt.getExpiresAt().isBefore(Instant.now())) {
            repository.delete(rt);   //만료된 것은 정리
            throw new BadCredentialsException("만료된 refresh 토큰입니다. 다시 로그인하세요");
        }

        String userUuid = rt.getUserUuid();
        repository.delete(rt);       //기존 refresh 는 1회용 → 즉시 폐기
        return issue(userUuid);      //새 refresh 발급(회전)
    }

    /** 로그아웃 시: refresh 토큰 폐기 (있으면 삭제) */
    @Transactional
    public void revoke(String presentedToken) {
        repository.findByToken(presentedToken).ifPresent(repository::delete);
    }

    /** 무작위 불투명 토큰 값 (JWT 아님, 의미 없는 랜덤) */
    private String newOpaqueToken() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }
}
