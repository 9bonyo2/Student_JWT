package com.basic.myspringboot.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
    /*
     * 로그인 여부를 직접 따지지 않는다. "/users/**" 는 이미 authenticated() 로
     * 보호돼 있으므로, 비로그인 사용자는 auditedLoginEntryPoint() 를 거쳐
     * 자동으로 /login 으로 보내지고, 로그인된 사용자는 바로 목록으로 간다.
     * ( 예전에는 무조건 /login 으로 보내, 로그인 중에 "홈으로"를 눌러도
     *   다시 로그인 화면이 뜨는 혼란스러운 동작이었다 )
     */
    @GetMapping("/")
    public String index() {
        return "redirect:/users/index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}