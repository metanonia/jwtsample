package com.metanonia.jwtsample.service;

import com.metanonia.jwtsample.core.CommonResponse;
import com.metanonia.jwtsample.core.security.AuthToken;
import com.metanonia.jwtsample.core.security.Role;
import com.metanonia.jwtsample.exception.LoginFailedException;
import com.metanonia.jwtsample.provider.security.JwtAuthToken;
import com.metanonia.jwtsample.provider.security.JwtAuthTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtAuthTokenProvider jwtAuthTokenProvider;
    private final static long LOGIN_RETENTION_MINUTES = 30;

    public CommonResponse login(JSONObject loginInfo) {
        String username = loginInfo.getString("uername");
        String password = loginInfo.getString("password");
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        //사용자 비밀번호 체크, 패스워드 일치하지 않는다면 Exception 발생 및 이후 로직 실행 안됨
        Authentication authentication = authenticationManagerBuilder
                .getObject()
                .authenticate(authenticationToken);

        //로그인 성공하면 인증 객체 생성 및 스프링 시큐리티 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Role role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .map(Role::of)
                .orElse(Role.UNKNOWN);

        // 정상 이용자 인지 확인
        if(true) {  // 정상이용자이면
            String UserInfo = "Tempo UserInfo";
            JwtAuthToken jwtAuthToken = (JwtAuthToken) createAuthToken(UserInfo);

            return CommonResponse.builder()
                    .code("LOGIN_SUCCESS")
                    .status(200)
                    .message(jwtAuthToken.getToken())
                    .build();
        }
        else {
            throw new LoginFailedException();
        }
    }

    public AuthToken createAuthToken(String UserInfo) {

        Date expiredDate = Date.from(LocalDateTime.now().plusMinutes(LOGIN_RETENTION_MINUTES).atZone(ZoneId.systemDefault()).toInstant());
        return jwtAuthTokenProvider.createAuthToken("username", "role", expiredDate);
    }
}
