package com.basic.myspringboot.security.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * [JWT 2단계] 토큰 갱신·로그아웃 요청 DTO.
 * 클라이언트가 보관하던 refresh 토큰을 보낸다.
 */
@Getter
@Setter
public class RefreshRequest {

    @NotBlank(message = "refreshToken 은 필수입니다")
    private String refreshToken;
}
