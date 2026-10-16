package com.basic.myspringboot.security.controller;

import com.basic.myspringboot.security.controller.dto.AuthRequest;
import com.basic.myspringboot.security.controller.dto.AuthResponse;
import com.basic.myspringboot.security.controller.dto.RefreshRequest;
import com.basic.myspringboot.security.controller.dto.SignUpRequest;
import com.basic.myspringboot.security.controller.dto.UserInfoResponse;
import com.basic.myspringboot.security.models.UserInfoUserDetails;
import com.basic.myspringboot.security.service.RefreshTokenService;
import com.basic.myspringboot.security.service.RefreshTokenService.IssuedToken;
import com.basic.myspringboot.security.service.UserInfoUserDetailsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.basic.myspringboot.security.jwt.JwtService;
import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/userinfos")
@RequiredArgsConstructor
public class UserInfoController {

    /** 회원가입으로 만들어지는 계정의 기본 권한 ( 관리자는 요청으로 받지 않는다 ) */
    private static final String DEFAULT_ROLE = "ROLE_USER";

    private final UserInfoRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserInfoUserDetailsService userDetailsService;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    /**
     * 회원가입. 권한은 서버가 ROLE_USER 로 고정한다.
     */
    @PostMapping("/new")
    public ResponseEntity<String> addNewUser(@Valid @RequestBody SignUpRequest request) {
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("이미 사용 중인 이메일입니다 : " + request.getEmail());
        }

        UserInfo userInfo = new UserInfo();
        userInfo.setName(request.getName());
        userInfo.setEmail(request.getEmail());
        //비밀번호는 반드시 암호화해서 저장한다
        userInfo.setPassword(passwordEncoder.encode(request.getPassword()));
        userInfo.setRoles(DEFAULT_ROLE);

        UserInfo savedUserInfo = repository.save(userInfo);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(savedUserInfo.getName() + " user added!!");
    }

    /**
     * 로그인. 인증에 실패하면 AuthenticationException 이 발생하고
     * DefaultExceptionAdvice 가 401 로 응답한다.
     *
     * [로그인 시도 제한 - bruteforce-demo] 잠금 확인(assertNotLocked)은 공통 지점인
     * UserInfoUserDetailsService.loadUserByUsername() 에서, 실패/성공 누적(onFailure/onSuccess)은
     * SecurityAuditListener 의 인증 이벤트 리스너에서 처리한다 - 둘 다 AuthenticationManager 를
     * 거치면 공통으로 실행되므로, 폼 로그인(/login-process)과 REST 로그인(여기)이 같은 로직을 공유한다.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateAndGetToken(@Valid @RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(),
                        authRequest.getPassword()
                ));

        //인증에 성공하면 principal 에 UserInfoUserDetails 가 들어 있다
        UserInfoUserDetails userDetails = (UserInfoUserDetails) authentication.getPrincipal();
        //[JWT 하드닝] 토큰 subject 로 email(PII) 대신 불투명 식별자(uuid)를 넣는다
        String accessToken = jwtService.generateToken(userDetails.getUuid());
        //[2단계] 로그인 시 refresh 토큰도 발급(서버 저장) → 짧은 access 만료 후 재발급에 사용
        String refreshToken = refreshTokenService.issue(userDetails.getUuid()).plainToken();
        return ResponseEntity.ok(AuthResponse.of(accessToken, refreshToken,
                jwtService.getAccessExpireSeconds(), UserInfoResponse.from(userDetails)));
    }

    /**
     * [2단계] 토큰 갱신. 만료된(또는 곧 만료될) access 대신 refresh 토큰을 제시하면,
     * 새 access + 새 refresh(회전)를 돌려준다. refresh 가 유효하지 않거나 만료면 401.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        //유효하지 않으면 BadCredentialsException → 401 (DefaultExceptionAdvice)
        //(재사용 탐지로 실패한 경우도 동일하게 401 — §RefreshTokenService.rotate 참고)
        IssuedToken rotated = refreshTokenService.rotate(request.getRefreshToken());
        UserInfoUserDetails userDetails = userDetailsService.loadUserByUuid(rotated.userUuid());
        String accessToken = jwtService.generateToken(userDetails.getUuid());
        return ResponseEntity.ok(AuthResponse.of(accessToken, rotated.plainToken(),
                jwtService.getAccessExpireSeconds(), UserInfoResponse.from(userDetails)));
    }

    /**
     * [2단계] 로그아웃. 제시한 refresh 토큰을 서버에서 폐기한다.
     * (access 는 stateless 라 만료까지 유효하므로, access 는 짧게 두는 것이 전제)
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest request) {
        refreshTokenService.revoke(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    /**
     * 로그인한 사용자 정보. 새로고침 후 토큰만 남아 있을 때 권한을 다시 확인하는 용도.
     * 토큰이 없거나 잘못되면 SecurityConfig 의 EntryPoint 가 401 을 응답한다.
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> me(@AuthenticationPrincipal UserInfoUserDetails userDetails) {
        return ResponseEntity.ok(UserInfoResponse.from(userDetails));
    }
}
