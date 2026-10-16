package com.basic.myspringboot.security.logging;

import com.basic.myspringboot.security.service.LoginAttemptService;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.LockedException;
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
 *
 * [로그인 시도 제한 - bruteforce-demo] 폼 로그인(/login-process)과 REST 로그인(/api/userinfos/login)
 * 모두 이 이벤트를 거치므로, LoginAttemptService.onSuccess/onFailure 도 여기 한 곳에서 호출해
 * 두 경로 모두 동일하게 실패 횟수를 누적·초기화한다.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class SecurityAuditListener {

    private final MeterRegistry meterRegistry;
    private final LoginAttemptService loginAttemptService;

    /** 로그인 성공 */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String user = event.getAuthentication().getName();
        log.info("[AUDIT] 로그인 성공 - user={}", mask(user));
        meterRegistry.counter("auth.events", "result", "success").increment();
        loginAttemptService.onSuccess(user);
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
        //이미 잠긴 계정에 대한 재시도(LockedException)는 실패 횟수를 추가로 누적하지 않는다.
        //UserInfoUserDetailsService.assertNotLocked() 에서 비밀번호 검증 전에 걸러진 거부일 뿐,
        //새로운 비밀번호 실패가 아니기 때문이다(그대로 누적하면 잠금이 계속 연장된다).
        if (!(event.getException() instanceof LockedException)) {
            loginAttemptService.onFailure(user);
        }
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
