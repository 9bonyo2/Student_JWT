package com.basic.myspringboot.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.function.Function;

/**
 * JWT 발급과 검증을 담당한다.
 *
 * 비밀 키는 소스에 두지 않고 application.properties 의 jwt.secret 에서 주입받는다.
 * ( 운영에서는 환경 변수 JWT_SECRET 으로 주입한다 )
 *
 * [#7/#4 하드닝] secret 이 유출되면 누구나 유효한 토큰(관리자 포함)을 위조할 수 있으므로,
 * 기동 시 약한/기본 secret 을 감지해 fail-closed 로 막는다(jwt.allow-insecure-secret=false).
 */
@Component
@Slf4j
public class JwtService {

    private static final SecureDigestAlgorithm<SecretKey, SecretKey> ALGORITHM = Jwts.SIG.HS256;

    //널리 알려진/샘플/이 저장소에 커밋된 실습용 기본값. 운영에서 쓰면 즉시 위조 위험.
    private static final Set<String> KNOWN_WEAK_SECRETS = Set.of(
            "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437", // 실습용 기본값(리포지토리 공개)
            "secret", "changeit", "your-256-bit-secret", "mySecretKey"
    );

    private final SecretKey key;
    private final long accessExpireSeconds;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-expire-seconds}") long accessExpireSeconds,
                      @Value("${jwt.allow-insecure-secret:false}") boolean allowInsecureSecret) {
        validateSecret(secret, allowInsecureSecret);
        //HS256 은 최소 256비트(32바이트) 이상의 키를 요구한다
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpireSeconds = accessExpireSeconds;
    }

    /**
     * secret 이 약하거나(짧음/공백) 알려진 기본값이면 위험하다.
     *  - allowInsecureSecret=false(운영/안전) : 기동 실패(fail-closed) 로 배포 사고를 막는다
     *  - allowInsecureSecret=true (실습/취약 데모) : 경고만 남기고 계속한다
     */
    private void validateSecret(String secret, boolean allowInsecureSecret) {
        boolean weak = secret == null
                || secret.isBlank()
                || secret.getBytes(StandardCharsets.UTF_8).length < 32   // HS256 최소 길이
                || KNOWN_WEAK_SECRETS.contains(secret.trim());
        if (!weak) {
            return;
        }
        String msg = "[JWT] 약한/기본 secret 이 감지되었습니다. secret 이 유출되면 누구나 토큰(관리자 포함)을 "
                + "위조할 수 있습니다. 운영에서는 환경변수 JWT_SECRET 으로 충분히 길고 무작위한 값을 주입하세요.";
        if (!allowInsecureSecret) {
            //fail-closed : 취약한 상태로 절대 기동하지 않는다
            throw new IllegalStateException(msg + " (실습용으로 계속하려면 jwt.allow-insecure-secret=true)");
        }
        log.warn("{} — jwt.allow-insecure-secret=true 로 계속합니다(실습 전용, 운영 금지).", msg);
    }

    /** 토큰 만료 시간 ( 초 ). 로그인 응답에 함께 내려준다 */
    public long getAccessExpireSeconds() {
        return accessExpireSeconds;
    }

    /**
     * [JWT 하드닝] 토큰 subject 로 email(PII) 대신 불투명 식별자(uuid)를 넣는다.
     * payload 는 base64 라 누구나 읽을 수 있으므로, 의미있는 정보를 남기지 않는다.
     */
    public String generateToken(String subject) {
        Date expireDate = Date.from(Instant.now().plusSeconds(accessExpireSeconds));

        return Jwts.builder()
                .signWith(key, ALGORITHM)
                .subject(subject)        // = UserInfo.uuid
                .issuedAt(new Date())
                .expiration(expireDate)
                .compact();
    }

    /** 토큰의 subject(= uuid)를 꺼낸다. 서명 불일치·만료면 여기서 JwtException 이 발생한다. */
    public String extractSubject(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * 토큰 subject 가 기대한 uuid 와 일치하고 만료되지 않았는지 확인한다.
     * 서명이 올바르지 않거나 만료된 토큰이면 extractSubject 에서 JwtException 이 발생한다.
     */
    public boolean validateToken(String token, String expectedUuid) {
        final String subject = extractSubject(token);
        return subject.equals(expectedUuid) && !isTokenExpired(token);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
