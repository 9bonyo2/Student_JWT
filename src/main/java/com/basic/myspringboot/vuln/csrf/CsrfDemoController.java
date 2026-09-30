package com.basic.myspringboot.vuln.csrf;

import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import com.basic.myspringboot.security.models.UserInfoUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * [ 교육용 - CSRF(Cross-Site Request Forgery) 시연 컨트롤러 ]
 *
 * ⚠️ 경고 : CSRF 를 체험하기 위한 강의용 엔드포인트다.
 *
 * CSRF 는 "로그인된 사용자의 브라우저"가 공격자의 페이지에 의해
 * 본인도 모르게 상태 변경 요청(예: 비밀번호 변경)을 보내게 되는 공격이다.
 * 세션+쿠키 기반 인증(Thymeleaf 폼 로그인)에서 문제가 된다.
 * ( JWT 를 Authorization 헤더로 보내는 REST 는 쿠키가 자동 전송되지 않아 CSRF 위험이 낮다 )
 *
 * 이 엔드포인트는 세션 인증(/users/**)이 필요하다.
 *   GET  /users/change-password   : 비밀번호 변경 폼
 *   POST /users/change-password   : 비밀번호 변경(상태 변경) - CSRF 의 표적
 */
@Controller
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class CsrfDemoController {

    private final UserInfoRepository userInfoRepository;
    private final PasswordEncoder passwordEncoder;

    /** 비밀번호 변경 폼 ( Thymeleaf. CSRF 가 켜지면 hidden _csrf 토큰이 자동 삽입된다 ) */
    @GetMapping("/change-password")
    public String form() {
        return "change-password";
    }

    /**
     * 비밀번호 변경 처리. 로그인된 사용자(세션 주체)의 비밀번호를 바꾼다.
     * CSRF 보호가 없으면, 공격자 페이지가 보낸 위조 요청도 그대로 실행되어 계정이 탈취된다.
     */
    @PostMapping("/change-password")
    public String changePassword(@RequestParam String newPassword,
                                 @AuthenticationPrincipal UserInfoUserDetails me,
                                 RedirectAttributes redirectAttributes) {
        UserInfo user = userInfoRepository.findByEmail(me.getUsername())
                .orElseThrow(() -> new IllegalStateException("세션 사용자를 찾을 수 없습니다"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userInfoRepository.save(user);

        log.warn("[AUDIT] 비밀번호 변경 - user={}", mask(me.getUsername()));

        //PRG(Post-Redirect-Get) : 성공 메시지는 flash 로 전달하고 다른 경로로 이동한다.
        //( 변경 폼에 머무르지 않고, 새로고침 시 폼 재제출도 방지 )
        redirectAttributes.addFlashAttribute("msg", me.getUsername() + " 의 비밀번호가 변경되었습니다.");
        return "redirect:/users/index";
    }

    private String mask(String email) {
        int at = email.indexOf('@');
        String local = at > 0 ? email.substring(0, at) : email;
        String domain = at > 0 ? email.substring(at) : "";
        return (local.length() <= 2 ? local.charAt(0) + "***" : local.substring(0, 2) + "***") + domain;
    }
}
