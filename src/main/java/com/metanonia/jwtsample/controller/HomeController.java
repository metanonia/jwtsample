package com.metanonia.jwtsample.controller;

import com.metanonia.jwtsample.core.CommonResponse;
import com.metanonia.jwtsample.service.JwtService;
import netscape.javascript.JSObject;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

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
    @PostMapping("/login")
    public CommonResponse signin(@RequestBody JSONObject loginInfo) {
        JSONObject jsonObject = new JSONObject();

        return jwtService.login(loginInfo);
    }
}
