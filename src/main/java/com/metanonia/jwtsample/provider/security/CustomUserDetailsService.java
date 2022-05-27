package com.metanonia.jwtsample.provider.security;

import com.metanonia.jwtsample.service.Hmac512PasswordEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Hmac512PasswordEncoder hmac = new Hmac512PasswordEncoder("salt");
        String encrypted = hmac.encode("1234");
        return User.builder()
                .username(username)
                .password(encrypted)
                .roles("USER")
                .build();
    }

    private User createSpringSecurityUser(String username) {
        List<GrantedAuthority> grantedAuthorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        return new User(username, "1234", grantedAuthorities);
    }
}
