package com.metanonia.jwtsample.controller;

import com.metanonia.jwtsample.core.CommonResponse;
import com.metanonia.jwtsample.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import netscape.javascript.JSObject;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

import static jdk.nashorn.internal.runtime.regexp.joni.Config.log;

@Slf4j
@Controller
public class HomeController {
    @Autowired
    JwtService jwtService;

    @GetMapping("/")
    public String home() {
        return "/home";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }

    @GetMapping("/logout")
    public String logout() {
        return "/logout";
    }

    @ResponseBody
    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public CommonResponse signin(@RequestParam HashMap<String,Object> loginInfo) {

        return jwtService.login(loginInfo);
    }
}
