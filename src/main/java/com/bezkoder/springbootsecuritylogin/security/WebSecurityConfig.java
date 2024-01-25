package com.bezkoder.springbootsecuritylogin.security;

import com.bezkoder.springbootsecuritylogin.jwt.AuthEntryPointJwt;
import com.bezkoder.springbootsecuritylogin.jwt.AuthTokenFilter;
import com.bezkoder.springbootsecuritylogin.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * WebSecurityConfig 클래스는 Spring Security 설정을 정의합니다.
 * 이 클래스는 JWT 기반 인증, 사용자 인증 서비스, 비밀번호 인코딩 등을 설정합니다.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Value("${spring.h2.console.path}")
    private String h2ConsolePath; // h2 콘솔 경로 설정을 위한 변수입니다.

    @Autowired
    UserDetailsServiceImpl userDetailsService; // 사용자 상세 서비스를 자동 주입합니다.

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler; // 인증되지 않은 접근 처리를 위한 핸들러를 자동 주입합니다.

    public void configure(WebSecurity web) throws Exception{
        web.debug(true);
    }

    /**
     * JWT 인증 필터 빈을 생성합니다.
     * 이 필터는 HTTP 요청에 포함된 JWT를 검증합니다.
     *
     * @return AuthTokenFilter JWT 인증 필터
     */
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    /**
     * DaoAuthenticationProvider 빈을 생성합니다.
     * 이는 사용자 인증 서비스와 비밀번호 인코더를 설정합니다.
     *
     * @return DaoAuthenticationProvider 인증 제공자
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // 사용자 상세 서비스를 설정합니다.
        authProvider.setPasswordEncoder(passwordEncoder()); // 비밀번호 인코더를 설정합니다.
        return authProvider;
    }

    /**
     * AuthenticationManager 빈을 생성합니다.
     * 이는 Spring Security 인증 메커니즘을 관리합니다.
     *
     * @param authConfig 인증 설정
     * @return AuthenticationManager 인증 관리자
     * @throws Exception 예외 처리
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * 비밀번호 인코더 빈을 생성합니다.
     * 이는 비밀번호를 안전하게 인코딩하는 데 사용됩니다.
     *
     * @return PasswordEncoder 비밀번호 인코더
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * SecurityFilterChain을 정의하여 HTTP 보안을 구성합니다.
     * 이 메서드는 CSRF 보호 비활성화, 세션 관리 전략, 인증 엔트리 포인트, 인증 규칙 등을 설정합니다.
     *
     * @param http HttpSecurity 설정 객체
     * @return SecurityFilterChain 보안 필터 체인
     * @throws Exception 예외 처리
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.csrf(csrf->csrf.disable()) // CSRF 보호를 비활성화합니다.
                .exceptionHandling(exception-> exception.authenticationEntryPoint(unauthorizedHandler)) // 예외 처리를 설정합니다.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 정책을 상태 없음으로 설정합니다.
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/auth/**").permitAll() // 특정 경로에 대한 접근을 허용합니다.
                                .requestMatchers("/api/test/**").permitAll()
                                .requestMatchers(h2ConsolePath + "/**").permitAll()
                                .anyRequest().authenticated()
                );
        http.headers(headers -> headers.frameOptions(frameOption ->frameOption.sameOrigin())); // h2 콘솔에 대한 헤더 설정을 변경합니다.
        http.authenticationProvider(authenticationProvider()); // 인증 제공자를 추가합니다.
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class); // 필터 체인에 JWT 필터를 추가합니다.
        return http.build(); // HttpSecurity 구성을 빌드합니다.
    }

}
