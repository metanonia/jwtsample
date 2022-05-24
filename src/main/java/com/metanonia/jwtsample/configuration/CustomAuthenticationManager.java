package com.metanonia.jwtsample.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Slf4j
public class CustomAuthenticationManager implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("Username = " + authentication.getPrincipal());
        return new UsernamePasswordAuthenticationToken(authentication.getPrincipal()
                , authentication.getCredentials()
                , authentication.getAuthorities());
    }
}
