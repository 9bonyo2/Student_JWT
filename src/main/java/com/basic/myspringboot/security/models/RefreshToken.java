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
 * [2단계 보강] 원문이 아니라 SHA-256 해시를 저장한다 — DB 가 유출돼도 해시만으로는
 * 재사용(로그인 유지)이 불가능하다. 클라이언트에는 원문을, DB 에는 해시만 남긴다.
 * [2단계 보강] 회전된(이미 사용된) 토큰은 즉시 삭제하지 않고 revoked=true 로 표시해
 * 재사용 탐지(§RefreshTokenService.rotate)에 활용한다.
 */
@Entity
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 무작위 불투명 refresh 토큰 값의 SHA-256 해시(hex). 원문은 DB 에 저장하지 않는다 */
    @Column(unique = true, nullable = false, length = 64)
    private String tokenHash;

    /** 소유자 식별자 (UserInfo.uuid) — refresh 성공 시 이 사용자로 새 access 를 발급한다 */
    @Column(nullable = false, length = 36)
    private String userUuid;

    /** 만료 시각. 지나면 재발급을 거부하고 삭제한다 */
    @Column(nullable = false)
    private Instant expiresAt;

    /** 회전(rotate)으로 폐기된 토큰이면 true. 폐기된 토큰이 다시 제시되면 탈취·재사용 신호다 */
    @Column(nullable = false)
    private boolean revoked;
}
