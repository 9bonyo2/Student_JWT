package com.basic.myspringboot.security.models;

import jakarta.persistence.*;
import lombok.*;

import java.util.Arrays;

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

    // roles 는 "ROLE_USER" 또는 "ROLE_ADMIN,ROLE_USER" 처럼 쉼표로 구분된 문자열이다
    public boolean isAdmin() {
        String value = roles == null ? "" : roles;
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .anyMatch("ROLE_ADMIN"::equals);
    }
}
