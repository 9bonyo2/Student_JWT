package com.basic.myspringboot.security.models;

import jakarta.persistence.*;
import lombok.*;

<<<<<<< HEAD
import java.util.Arrays;
import java.util.UUID;

=======
>>>>>>> origin/feature/jwt-security-demo
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class UserInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    //"ROLE_USER" 또는 "ROLE_ADMIN,ROLE_USER" 처럼 쉼표로 구분해 저장한다
    @Column(nullable = false)
    private String roles;
<<<<<<< HEAD

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
=======
>>>>>>> origin/feature/jwt-security-demo
}
