package com.basic.myspringboot.security.models;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * [JWT 2단계] Refresh 토큰 (서버 저장 방식).
 *
 * access 토큰은 짧게 두고, 만료되면 이 refresh 토큰으로 새 access 를 발급받는다.
 * refresh 토큰은 JWT 가 아니라 "무작위 불투명 문자열"이며, 서버 DB 에 저장한다.
 * 서버가 들고 있으므로 로그아웃·유출 시 삭제(폐기)할 수 있고, 갱신 때마다 교체(회전)한다.
 *
 * 운영 주의: 실제로는 토큰 원문 대신 해시를 저장하는 것이 더 안전하다(여기선 실습용으로 원문 저장).
 */
@Entity
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 무작위 불투명 refresh 토큰 값 (JWT 아님) */
    @Column(unique = true, nullable = false, length = 100)
    private String token;

    /** 소유자 식별자 (UserInfo.uuid) — refresh 성공 시 이 사용자로 새 access 를 발급한다 */
    @Column(nullable = false, length = 36)
    private String userUuid;

    /** 만료 시각. 지나면 재발급을 거부하고 삭제한다 */
    @Column(nullable = false)
    private Instant expiresAt;
}
