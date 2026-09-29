package com.basic.myspringboot.vuln.idor;

import com.basic.myspringboot.security.models.UserInfoUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * [ 교육용 - IDOR / 접근 제어 시연 컨트롤러 ]
 *
 * ⚠️ 경고 : 취약점을 체험하기 위한 강의용 엔드포인트다. 실제 서비스에 배포하지 말 것.
 *
 * 이 경로(/api/idor/**)는 SecurityConfig 의 /api/** 규칙에 따라 "인증"이 필요하다.
 * ( IDOR 은 '로그인은 되었지만 남의 것에 접근' 하는 취약점이므로, 인증이 전제되어야 의미가 있다 )
 *
 * 비교 실습 :
 *   GET /api/idor/profiles/{id}       (🔴 취약 : 소유권 검사 없음)
 *   GET /api/idor/profiles-safe/{id}  (🟢 안전 : 본인 또는 관리자만)
 */
@RestController
@RequestMapping("/api/idor")
@RequiredArgsConstructor
public class IdorDemoController {

    private final IdorDemoService idorDemoService;

    /** 🔴 취약 : 로그인만 하면 임의의 {id} 프로필을 조회할 수 있다 */
    @GetMapping("/profiles/{id}")
    public ProfileResponse getProfileVulnerable(@PathVariable Long id) {
        return idorDemoService.getProfileVulnerable(id);
    }

    /** 🟢 안전 : 본인 또는 관리자만 조회 가능(그 외 403) */
    @GetMapping("/profiles-safe/{id}")
    public ProfileResponse getProfileSecure(@PathVariable Long id,
                                            @AuthenticationPrincipal UserInfoUserDetails me) {
        return idorDemoService.getProfileSecure(id, me);
    }
}
