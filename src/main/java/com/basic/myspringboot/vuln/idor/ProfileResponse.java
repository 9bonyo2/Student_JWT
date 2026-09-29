package com.basic.myspringboot.vuln.idor;

import com.basic.myspringboot.security.models.UserInfo;

/**
 * IDOR 데모 응답 DTO.
 *
 * 비밀번호(password) 는 노출하지 않는다. ( IDOR 자체에 집중하기 위한 최소 필드 )
 * 요청한 {id} 에 따라 다른 사용자의 정보가 조회되는지가 이 데모의 핵심이다.
 */
public record ProfileResponse(Long id, String name, String email, String roles) {

    public static ProfileResponse from(UserInfo u) {
        return new ProfileResponse(u.getId(), u.getName(), u.getEmail(), u.getRoles());
    }
}
