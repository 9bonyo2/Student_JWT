package com.basic.myspringboot.security.controller.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

/**
 * 로그인 응답 DTO.
 *
 * 토큰 문자열만 돌려주면 클라이언트가 만료 시간을 알 수 없고,
 * Authorization 헤더에 어떤 형식으로 넣어야 하는지도 드러나지 않는다.
 * 권한( roles )도 함께 돌려주어 클라이언트가 토큰을 해석하지 않고도 화면을 구성할 수 있게 한다.
 */
@Getter
@AllArgsConstructor
public class AuthResponse {

    /** 발급된 JWT 액세스 토큰 */
    private String accessToken;

    /** [2단계] 갱신에 쓰는 refresh 토큰 (서버 저장·회전) */
    private String refreshToken;

    /** Authorization 헤더에 사용할 토큰 형식 ( Bearer ) */
    private String tokenType;

    /** 토큰 만료까지 남은 시간 ( 초 ) */
    private long expiresIn;

    /** 로그인한 사용자 이메일 */
    private String email;

    /** 로그인한 사용자 이름 */
    private String name;

    /** 권한 목록 ( 화면 표시용. 실제 권한 검사는 서버가 한다 ) */
    private List<String> roles;

    public static AuthResponse of(String accessToken, String refreshToken, long expiresIn, UserInfoResponse user) {
        return new AuthResponse(accessToken, refreshToken, "Bearer", expiresIn,
                user.getEmail(), user.getName(), user.getRoles());
    }
}
