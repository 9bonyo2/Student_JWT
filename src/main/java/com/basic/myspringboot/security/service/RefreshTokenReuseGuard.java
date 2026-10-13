package com.basic.myspringboot.security.service;

import com.basic.myspringboot.security.models.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * [JWT 2단계 보강] 재사용(탈취) 탐지 시 "해당 사용자의 모든 refresh 토큰 폐기"를 별도 트랜잭션으로 커밋한다.
 *
 * RefreshTokenService.rotate() 는 재사용을 감지하면 곧바로 BadCredentialsException 을 던지는데,
 * 그 메서드 자체가 @Transactional 이라 예외가 발생하면 트랜잭션이 롤백된다. 같은 트랜잭션에서
 * 폐기(delete)를 실행하면 그 삭제까지 롤백으로 함께 취소돼 버리므로, 자기 자신을 호출(self-invocation)해도
 * 프록시를 거치지 않아 REQUIRES_NEW 가 적용되지 않는다 — 그래서 별도 빈으로 분리했다.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenReuseGuard {

    private final RefreshTokenRepository repository;

    /** 바깥 트랜잭션의 롤백과 무관하게 즉시 커밋되어야 하므로 REQUIRES_NEW */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAll(String userUuid) {
        repository.deleteAllByUserUuid(userUuid);
    }
}
