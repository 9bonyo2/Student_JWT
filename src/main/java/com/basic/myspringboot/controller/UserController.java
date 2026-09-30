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

    @GetMapping("/index")
    public String index(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "index";
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

    //[CSRF 하드닝] 삭제는 상태 변경이므로 GET 이 아니라 POST 로 받는다.
    //  - GET 이면 CSRF 토큰이 적용되지 않아 <img src=".../delete/1"> 로도 삭제가 트리거된다.
    //  - POST 로 바꾸면 Thymeleaf 폼의 _csrf 토큰이 요구되어 위조 요청이 차단된다.
    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable("id") long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid user Id:" + id));
        userRepository.delete(user);
        return "redirect:/users/index";
    }

    @GetMapping("/thymeleaf")
    public String leaf(Model model) {
        model.addAttribute("name", "스프링부트!");
        return "leaf";
    }
}