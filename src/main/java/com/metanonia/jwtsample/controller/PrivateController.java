package com.metanonia.jwtsample.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/private")
public class PrivateController {
    @GetMapping("/")
    public String orderPage() {
        return "/private/home";
    }
}
