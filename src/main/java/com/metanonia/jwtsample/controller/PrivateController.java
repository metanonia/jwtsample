package com.metanonia.jwtsample.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/private")
public class PrivateController {
    @GetMapping("/")
    public String privateHome(@AuthenticationPrincipal User pricipal) {
        log.info(pricipal.toString());
        return "/private/home";
    }
}
