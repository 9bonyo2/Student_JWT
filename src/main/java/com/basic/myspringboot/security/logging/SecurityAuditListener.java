package com.basic.myspringboot.security.logging;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * [ 보안 감사 로깅 - 인증 이벤트 ] (OWASP #9 로깅·경보 실패 대응)
 *
 * Spring Security 가 발행하는 인증 성공/실패 이벤트를 받아 감사 로그로 남긴다.
 * ( 폼 로그인 /login-process, REST 로그인 /api/userinfos/login 모두 AuthenticationManager 를
 *   거치므로 이벤트가 발생한다 )
 *
 * 원칙:
 *   - 민감정보(비밀번호·JWT 토큰)는 절대 로그에 남기지 않는다.
 *   - 사용자 식별자(이메일)는 마스킹한다.
 *   - "[AUDIT]" 태그로 감사 로그를 구분해 나중에 SIEM 등에서 필터링하기 쉽게 한다.
 *
 * Micrometer 집계: 로그와 별개로 auth.events 카운터(result=success|failure)를 남긴다.
 * /actuator/metrics/auth.events 로 조회하며, 이 엔드포인트는 /actuator/** 에 걸린
 * ROLE_ADMIN 인증 요구를 그대로 적용받는다(SecurityConfig 수정 불필요).
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class SecurityAuditListener {

    private final MeterRegistry meterRegistry;

    /** 로그인 성공 */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String user = event.getAuthentication().getName();
        log.info("[AUDIT] 로그인 성공 - user={}", mask(user));
        meterRegistry.counter("auth.events", "result", "success").increment();
    }

    /**
     * 로그인 실패 ( 비밀번호 불일치, 없는 사용자 등 ).
     * 짧은 시간에 이 로그가 다수 발생하면 무차별 대입(brute force) 공격 신호다.
     */
    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String user = String.valueOf(event.getAuthentication().getName());
        String reason = event.getException().getClass().getSimpleName();
        log.warn("[AUDIT] 로그인 실패 - user={}, reason={}", mask(user), reason);
        meterRegistry.counter("auth.events", "result", "failure").increment();
    }

    /**
     * 사용자 식별자(이메일 등) 마스킹. 앞 2글자만 노출한다.
     * 예) user@aa.com -> us***@aa.com
     */
    private String mask(String value) {
        if (value == null || value.isBlank()) {
            return "(unknown)";
        }
        int at = value.indexOf('@');
        String local = (at > 0) ? value.substring(0, at) : value;
        String domain = (at > 0) ? value.substring(at) : "";
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.substring(0, 2) + "***" + domain;
    }
}
