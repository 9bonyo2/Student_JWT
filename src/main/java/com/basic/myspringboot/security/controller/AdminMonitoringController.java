package com.basic.myspringboot.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminMonitoringController {
    @GetMapping("/admin/monitoring")
    public String monitoring() {
        return "admin/monitoring";
    }
}
