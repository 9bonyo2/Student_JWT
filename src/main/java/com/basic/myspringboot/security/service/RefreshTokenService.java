package com.basic.myspringboot.security.service;

import com.basic.myspringboot.security.models.RefreshToken;
import com.basic.myspringboot.security.models.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * [JWT 2단계] Refresh 토큰 발급·회전·폐기.
 *
 *  - issue  : 로그인 시 새 refresh 토큰을 만들어 DB 에 저장(해시만 저장, 원문은 클라이언트에만 반환)
 *  - rotate : refresh 로 새 access 를 받을 때, 기존 refresh 를 폐기하고 새 refresh 로 교체(1회용·회전)
 *  - revoke : 로그아웃 시 refresh 토큰 삭제(폐기)
 *
 * 회전(rotation) 덕분에, 한 번 쓴 refresh 는 즉시 무효가 되어 탈취·재사용에 강해진다.
 *
 * [2단계 보강 — 재사용 탐지 + 해시 저장] (06_JWT_Security.md §4-5 "운영 보강 포인트" 반영)
 *   - 해시 저장: DB 에는 토큰 원문이 아니라 SHA-256 해시만 둔다. DB 가 유출돼도
 *     해시만으로는 로그인을 유지할 수 없다(원문을 복원할 수 없으므로).
 *   - 재사용 탐지: rotate() 에서 기존 토큰을 즉시 삭제하는 대신 revoked=true 로 표시해 남겨둔다.
 *     이미 회전(폐기)된 토큰이 다시 제시되면 "탈취 후 재사용"으로 간주해, 해당 사용자의
 *     모든 refresh 토큰을 일괄 폐기한다(공격자·정상 사용자 모두 재로그인 필요 — 선제적 차단).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final RefreshTokenReuseGuard reuseGuard;

    @Value("${jwt.refresh-expire-seconds}")
    private long refreshExpireSeconds;

    /** rotate()/issue() 가 호출자에게 돌려주는 결과. 원문 토큰은 여기로만 전달되고 DB 에는 남지 않는다 */
    public record IssuedToken(String plainToken, String userUuid, Instant expiresAt) {
    }

    /** 로그인 시: 사용자(uuid)에 대한 새 refresh 토큰 발급·저장(해시만 저장) */
    @Transactional
    public IssuedToken issue(String userUuid) {
        String plainToken = newOpaqueToken();
        Instant expiresAt = Instant.now().plusSeconds(refreshExpireSeconds);

        RefreshToken rt = new RefreshToken();
        rt.setTokenHash(sha256Hex(plainToken));
        rt.setUserUuid(userUuid);
        rt.setExpiresAt(expiresAt);
        rt.setRevoked(false);
        repository.save(rt);

        return new IssuedToken(plainToken, userUuid, expiresAt);
    }

    /**
     * 갱신 시: 제시된 refresh 가 유효하면 폐기하고 새 refresh 로 교체(회전).
     * 이미 폐기(회전)된 토큰이 다시 제시되면 재사용(탈취) 신호로 보고 해당 사용자의
     * 모든 refresh 를 일괄 폐기한다.
     * 유효하지 않거나 만료면 401(BadCredentialsException) 로 처리된다.
     */
    @Transactional
    public IssuedToken rotate(String presentedPlainToken) {
        String presentedHash = sha256Hex(presentedPlainToken);
        RefreshToken rt = repository.findByTokenHash(presentedHash)
                .orElseThrow(() -> new BadCredentialsException("유효하지 않은 refresh 토큰입니다"));

        if (rt.isRevoked()) {
            //[재사용 탐지] 이미 회전되어 폐기된 토큰이 다시 들어옴 → 탈취 후 재사용 의심
            //주의: 바로 아래에서 예외를 던지면 이 메서드(@Transactional)는 롤백된다. 같은 트랜잭션에서
            //폐기(delete)를 실행하면 그 삭제까지 함께 취소되므로, 별도 빈(RefreshTokenReuseGuard)의
            //REQUIRES_NEW 트랜잭션으로 분리해 즉시 커밋해야 실제로 폐기된다.
            log.warn("[AUDIT] refresh 토큰 재사용 감지 - userUuid={} - 해당 사용자의 모든 refresh 토큰을 폐기합니다", rt.getUserUuid());
            reuseGuard.revokeAll(rt.getUserUuid());
            throw new BadCredentialsException("재사용이 감지되어 모든 세션이 종료되었습니다. 다시 로그인하세요");
        }

        if (rt.getExpiresAt().isBefore(Instant.now())) {
            repository.delete(rt);   //만료된 것은 정리
            throw new BadCredentialsException("만료된 refresh 토큰입니다. 다시 로그인하세요");
        }

        //기존 refresh 는 1회용 → 삭제 대신 revoked 표시(재사용 탐지를 위해 남겨둠)
        rt.setRevoked(true);
        repository.save(rt);
        return issue(rt.getUserUuid());      //새 refresh 발급(회전)
    }

    /** 로그아웃 시: refresh 토큰 폐기 (있으면 삭제) */
    @Transactional
    public void revoke(String presentedPlainToken) {
        repository.findByTokenHash(sha256Hex(presentedPlainToken)).ifPresent(repository::delete);
    }

    /** 무작위 불투명 토큰 값 (JWT 아님, 의미 없는 랜덤) */
    private String newOpaqueToken() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }

    /** 토큰 원문의 SHA-256 해시를 hex 문자열로 반환 */
    private String sha256Hex(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            //SHA-256 은 모든 JVM 이 기본 제공 → 실질적으로 발생하지 않는다
            throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다", e);
        }
    }
}
