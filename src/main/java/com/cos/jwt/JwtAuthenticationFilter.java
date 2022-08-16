package com.cos.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 존재
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작.

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

   private final AuthenticationManager authenticationManager;

   // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("JwtAuthenticationFilter : 로그인 시도중 ");
        
        // 1. username, password 받음
        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도 -> PricipalDetailsService 호출 loadUserByUsername 실행
        // 3. PricipalDetails를 세션에 담음
        // 4. JWT토큰을 만들어서 응답

        return super.attemptAuthentication(request, response);
    }
}
