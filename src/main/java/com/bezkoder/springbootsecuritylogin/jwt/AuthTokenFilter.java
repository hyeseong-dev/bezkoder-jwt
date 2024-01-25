package com.bezkoder.springbootsecuritylogin.jwt;

import com.bezkoder.springbootsecuritylogin.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * AuthTokenFilter 클래스는 Spring Security의 OncePerRequestFilter를 상속받아
 * HTTP 요청을 필터링하는 클래스입니다.
 * 이 클래스는 사용자의 인증 상태를 JWT 토큰을 통해 검증하고,
 * 유효한 토큰인 경우 Spring Security의 SecurityContext에 인증 정보를 설정합니다.
 */
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /**
     * 실제 필터링 로직을 수행하는 메서드입니다.
     * HTTP 요청에서 JWT 토큰을 추출하고 이를 검증한 후,
     * 유효한 토큰이면 해당 사용자의 인증 정보를 생성하여 SecurityContext에 설정합니다.
     *
     * @param request HTTP 요청 객체
     * @param response HTTP 응답 객체
     * @param filterChain 필터 체인
     * @throws ServletException 필터 실행 중 발생한 예외
     * @throws IOException 입출력 처리 중 발생한 예외
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // HTTP 요청으로부터 JWT 토큰을 추출합니다.
            String jwt = parseJwt(request);

            // 추출된 JWT 토큰이 존재하고 유효한 경우의 로직을 실행합니다.
            if (jwt != null && jwtUtils.validateJwtToken(jwt)){
                // 토큰으로부터 사용자 이름을 추출합니다.
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // 사용자 이름을 기반으로 사용자의 상세 정보를 로드합니다.
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 사용자의 인증 정보를 생성합니다. 이 정보는 인증된 사용자를 나타냅니다.
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                // 현재 요청에 대한 세부 정보를 인증 객체에 설정합니다.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Spring Security의 SecurityContext에 인증 정보를 설정합니다.
                // 이는 현재 사용자가 인증되었음을 시스템에 알립니다.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // 인증 과정에서 발생하는 모든 예외를 로깅합니다.
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }
        // 필터 체인을 계속 진행합니다. 이는 다음 필터나 최종적으로는 리소스에 대한 요청을 처리합니다.
        filterChain.doFilter(request, response);
    }

    /**
     * HTTP 요청으로부터 JWT 토큰을 추출하는 메서드입니다.
     *
     * @param request HTTP 요청 객체
     * @return 추출된 JWT 토큰 문자열, 토큰이 없으면 null 반환
     */
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromCookies(request);
        return jwt;
    }
}
