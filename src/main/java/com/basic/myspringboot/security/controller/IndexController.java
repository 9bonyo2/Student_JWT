package com.basic.myspringboot.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {
    @GetMapping("/")
    public String index() {
        //return "redirect:/login";
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}