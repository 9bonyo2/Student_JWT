package com.basic.myspringboot.security.models;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class UserInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //[JWT 하드닝] 토큰 subject 로 쓰는 불투명 식별자.
    //  로그인에 쓰는 email(PII) 대신 이 값을 토큰에 담아, payload 에 의미있는 정보가 남지 않게 한다.
    //  외부로 바뀔 일이 없고(updatable=false), 저장 직전 자동 생성된다(@PrePersist).
    @Column(unique = true, nullable = false, updatable = false, length = 36)
    private String uuid;

    @Column(nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    //"ROLE_USER" 또는 "ROLE_ADMIN,ROLE_USER" 처럼 쉼표로 구분해 저장한다
    @Column(nullable = false)
    private String roles;

    //[로그인 시도 제한 - bruteforce-demo] 연속 로그인 실패 횟수. 로그인 성공 시 0으로 초기화된다.
    @Column(nullable = false)
    private int failedLoginCount;

    //[로그인 시도 제한 - bruteforce-demo] 이 시각 이전까지는 비밀번호가 맞아도 로그인을 거부한다.
    //  null 이면 잠겨 있지 않은 상태. LoginAttemptService 가 설정/해제한다.
    private Instant lockedUntil;

    /** 저장 직전 uuid 가 비어 있으면 무작위로 채운다(시드·회원가입 등 모든 생성 경로 공통). */
    @PrePersist
    public void ensureUuid() {
        if (uuid == null || uuid.isBlank()) {
            uuid = UUID.randomUUID().toString();
        }
    }

    // roles 는 "ROLE_USER" 또는 "ROLE_ADMIN,ROLE_USER" 처럼 쉼표로 구분된 문자열이다
    public boolean isAdmin() {
        String value = roles == null ? "" : roles;
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .anyMatch("ROLE_ADMIN"::equals);
    }
}
