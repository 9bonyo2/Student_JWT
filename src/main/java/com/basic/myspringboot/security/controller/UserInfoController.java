package com.basic.myspringboot.security.controller;

import com.basic.myspringboot.security.controller.dto.AuthRequest;
import com.basic.myspringboot.security.controller.dto.AuthResponse;
import com.basic.myspringboot.security.controller.dto.SignUpRequest;
import com.basic.myspringboot.security.controller.dto.UserInfoResponse;
import com.basic.myspringboot.security.models.UserInfoUserDetails;
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
        String token = jwtService.generateToken(userDetails.getUsername());
        return ResponseEntity.ok(AuthResponse.of(token, jwtService.getAccessExpireSeconds(),
                UserInfoResponse.from(userDetails)));
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
