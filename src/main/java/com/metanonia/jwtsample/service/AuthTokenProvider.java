package com.metanonia.jwtsample.service;

import org.springframework.security.core.Authentication;

import java.util.Date;

public interface AuthTokenProvider<T> {
    T createAuthToken(String id, String role, Date expiredDate);
    T convertAuthToken(String token);
    Authentication getAuthentication(T authToken);
}
