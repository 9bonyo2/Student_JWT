package com.basic.myspringboot.security.service;

import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * [ 로그인 시도 제한 - bruteforce-demo ] (OWASP #7)
 *
 * 같은 계정에 비밀번호를 연속으로 틀리면(Burp Intruder 같은 자동화 도구로 반복 요청하는 경우 포함)
 * 일정 횟수 이후 계정을 일정 시간 잠가, 무차별 대입(brute force) 공격의 성공 확률을 낮춘다.
 *
 * 흐름: 폼 로그인(/login-process)과 REST 로그인(/api/userinfos/login) 모두 AuthenticationManager 를
 * 거치므로, 공통 지점에 걸어 두 경로에 동일하게 적용한다.
 *   1) UserInfoUserDetailsService.loadUserByUsername() 이 비밀번호 검증 전에
 *      assertNotLocked(email) 로 잠금 여부를 확인한다 (잠겨 있으면 즉시 거부).
 *   2) SecurityAuditListener 가 AuthenticationSuccessEvent/AbstractAuthenticationFailureEvent 를
 *      받아 onSuccess(email)/onFailure(email) 를 호출한다.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    private final UserInfoRepository repository;

    @Value("${login.lockout.max-attempts}")
    private int maxAttempts;

    @Value("${login.lockout.duration-seconds}")
    private long lockDurationSeconds;

    /** 잠겨 있으면 LockedException 을 던진다(비밀번호 검증 전에 즉시 차단). */
    @Transactional(readOnly = true)
    public void assertNotLocked(String email) {
        repository.findByEmail(email).ifPresent(user -> {
            Instant lockedUntil = user.getLockedUntil();
            if (lockedUntil != null && lockedUntil.isAfter(Instant.now())) {
                long remainingSeconds = Duration.between(Instant.now(), lockedUntil).getSeconds() + 1;
                throw new LockedException(
                        "로그인 시도 횟수를 초과하여 계정이 잠겼습니다. 약 " + remainingSeconds + "초 후 다시 시도하세요");
            }
        });
    }

    /** 로그인 성공 시 실패 횟수와 잠금을 초기화한다. */
    @Transactional
    public void onSuccess(String email) {
        repository.findByEmail(email).ifPresent(user -> {
            if (user.getFailedLoginCount() != 0 || user.getLockedUntil() != null) {
                user.setFailedLoginCount(0);
                user.setLockedUntil(null);
                repository.save(user);
            }
        });
    }

    /** 로그인 실패 시 호출. 실패 횟수를 누적하고, 임계치를 넘으면 계정을 잠근다. */
    @Transactional
    public void onFailure(String email) {
        repository.findByEmail(email).ifPresent(user -> {
            int count = user.getFailedLoginCount() + 1;
            user.setFailedLoginCount(count);
            if (count >= maxAttempts) {
                user.setLockedUntil(Instant.now().plusSeconds(lockDurationSeconds));
                log.warn("[AUDIT] 로그인 시도 제한 - 계정 잠금 - user={}, 실패 횟수={}, 잠금 시간={}초",
                        mask(email), count, lockDurationSeconds);
            }
            repository.save(user);
        });
    }

    /** 이메일 마스킹. 앞 2글자만 노출한다. (SecurityAuditListener 와 동일한 규칙) */
    private String mask(String value) {
        int at = value.indexOf('@');
        String local = (at > 0) ? value.substring(0, at) : value;
        String domain = (at > 0) ? value.substring(at) : "";
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.substring(0, 2) + "***" + domain;
    }
}
