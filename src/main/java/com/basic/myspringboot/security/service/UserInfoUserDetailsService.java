package com.basic.myspringboot.security.service;

import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import com.basic.myspringboot.security.models.UserInfoUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserInfoUserDetailsService implements UserDetailsService {

    private final UserInfoRepository repository;
    private final LoginAttemptService loginAttemptService;

    /**
     * [로그인 시도 제한 - bruteforce-demo] 폼 로그인(/login-process)과 REST 로그인(/api/userinfos/login)
     * 모두 AuthenticationManager -> DaoAuthenticationProvider 를 거치며 결국 이 메서드를 호출하므로,
     * 잠금 여부 확인을 여기 한 곳에 두면 두 경로 모두 비밀번호 검증 전에 동일하게 차단된다.
     */
    @Override
    public UserDetails loadUserByUsername(String username)
         throws UsernameNotFoundException {
        loginAttemptService.assertNotLocked(username);
        Optional<UserInfo> optionalUserInfo = repository.findByEmail(username);
        return optionalUserInfo.map(userInfo -> new UserInfoUserDetails(userInfo))
                //optionalUserInfo.map(UserInfoUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("user not found " + username));

    }

    /**
     * [JWT 하드닝] 토큰 subject(uuid) 로 사용자를 로드한다.
     * 세션 폼 로그인은 email 로 조회(loadUserByUsername)하고, JWT 필터는 uuid 로 조회한다.
     */
    public UserInfoUserDetails loadUserByUuid(String uuid) throws UsernameNotFoundException {
        return repository.findByUuid(uuid)
                .map(UserInfoUserDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("user not found (uuid)"));
    }

}