package com.metanonia.jwtsample.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/feed")
public class FeedController {
    @GetMapping("/order")
    public String orderPage() {
        return "/feed/order";
    }
}
