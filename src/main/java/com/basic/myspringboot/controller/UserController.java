package com.basic.myspringboot.controller;

import com.basic.myspringboot.controller.dto.UserDTO;
import com.basic.myspringboot.entity.User;
import com.basic.myspringboot.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserRepository userRepository;

    //[안전 ✅][XSS 하드닝] index.html 은 th:text(자동 이스케이프)로 렌더링한다.
    //  - 이름에 <script> 등을 넣어도 문자열 그대로 화면에 표시될 뿐 실행되지 않는다.
    @GetMapping("/index")
    public String index(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "index";
    }

    //[취약 ⚠️ - Stored XSS 공격 재현 실습 전용]
    //  같은 데이터(users)를 index-vuln.html 로 내려주는데, 그 템플릿은 이름을 th:utext(이스케이프 없음)로 렌더링한다.
    //  - 회원가입(이름 필드)에 <script>...</script> 를 넣고 저장하면,
    //    이 목록 페이지를 "보는 모든 사용자(관리자 포함)" 의 브라우저에서 그 스크립트가 그대로 실행된다.
    //  - 실무에서는 절대 두면 안 되는 안티패턴이다. 오직 공격 재현 실습을 위해 남긴다.
    //  - 방어 : 이 핸들러/템플릿을 제거하고 위의 안전한 /index(th:text) 만 쓰면 재현이 불가능해진다.
    @GetMapping("/index-vuln")
    public String indexVulnerable(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "index-vuln";
    }

    @GetMapping("/signup")
    public String showSignUpForm(@ModelAttribute("userForm") User user) {
        return "add-user";
    }

    @PostMapping("/adduser")
    public String addUser(@Valid @ModelAttribute("userForm") User user,
                          Errors result, Model model) {
        if (result.hasErrors()) {
            return "add-user";
        }
        userRepository.save(user);
        model.addAttribute("users", userRepository.findAll());
        return "index";
        //return "redirect:/index";
    }

    @GetMapping("/edit/{id}")
    public String showUpdateForm(@PathVariable("id") long id,
                                 Model model) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid user Id:" + id));
        //update-user.html 은 th:object="${userForm}" 로 바인딩하므로 userForm 으로 담는다
        model.addAttribute("userForm", user);
        return "update-user";
    }
    @PostMapping("/update/{id}")
    public String updateUser(@PathVariable long id,
                             @Valid @ModelAttribute("userForm") User user,
                             BindingResult result) {
        if (result.hasErrors()) {
            user.setId(id);
            return "update-user";
        }
        userRepository.save(user);
        return "redirect:/users/index";   //존재하는 경로로 리다이렉트
    }

    //[안전 ✅][CSRF 하드닝] 삭제는 상태 변경이므로 GET 이 아니라 POST 로 받는다.
    //  - Thymeleaf 삭제 폼(index.html)이 hidden _csrf 토큰을 자동 삽입한다.
    //  - 토큰이 없거나 틀린 위조 요청은 403 으로 차단된다.
    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable("id") long id) {
        deleteById(id);
        return "redirect:/users/index";
    }

    //[취약 ⚠️ - 예전 방식 / CSRF 공격 재현 실습 전용]
    //  같은 경로(/users/delete/{id}) 이지만 HTTP 메서드가 GET 이라 위 POST 와 별도 핸들러로 매핑된다.
    //  - GET 은 CSRF 토큰 검증 대상이 아니므로(안전 메서드로 취급) 토큰 없이도 실행된다.
    //  - 따라서 공격자 페이지에 아래 한 줄만 넣어도, 로그인된 피해자의 세션 쿠키(JSESSIONID)가
    //    자동 첨부되어 삭제가 트리거된다 :
    //        <img src="http://localhost:8080/users/delete/1">
    //  - 실무에서는 절대 두면 안 되는 안티패턴이다. 오직 공격 재현 실습을 위해 남긴다.
    //  - 방어 : 이 GET 핸들러를 제거하고 위의 POST(+_csrf 토큰) 만 남기면 재현이 불가능해진다.
    @GetMapping("/delete/{id}")
    public String deleteUserLegacyVulnerable(@PathVariable("id") long id) {
        deleteById(id);
        return "redirect:/users/index";
    }

    //삭제 공통 로직 (안전 POST / 취약 GET 이 함께 사용)
    private void deleteById(long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid user Id:" + id));
        userRepository.delete(user);
    }

    @GetMapping("/thymeleaf")
    public String leaf(Model model) {
        model.addAttribute("name", "스프링부트!");
        return "leaf";
    }
}