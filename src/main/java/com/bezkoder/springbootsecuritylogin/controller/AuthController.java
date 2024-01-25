package com.bezkoder.springbootsecuritylogin.controller;

import com.bezkoder.springbootsecuritylogin.model.ERole;
import com.bezkoder.springbootsecuritylogin.model.Role;
import com.bezkoder.springbootsecuritylogin.model.User;
import com.bezkoder.springbootsecuritylogin.request.LoginRequest;
import com.bezkoder.springbootsecuritylogin.jwt.JwtUtils;
import com.bezkoder.springbootsecuritylogin.repository.RoleRepository;
import com.bezkoder.springbootsecuritylogin.repository.UserRepository;
import com.bezkoder.springbootsecuritylogin.request.SignupRequest;
import com.bezkoder.springbootsecuritylogin.response.MessageResponse;
import com.bezkoder.springbootsecuritylogin.response.UserInfoResponse;
import com.bezkoder.springbootsecuritylogin.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * AuthController 클래스는 인증, 회원가입과 관련된 HTTP 요청을 처리합니다.
 * 사용자의 로그인 요청을 처리하고 JWT 쿠키를 반환합니다.
 */
/**
 * AuthController 클래스는 인증 및 회원가입과 관련된 HTTP 요청을 처리합니다.
 * 이 클래스는 사용자 로그인 및 회원가입 요청을 처리하고, JWT 기반의 인증을 수행합니다.
 */
@CrossOrigin(origins="*", maxAge=3600) // 모든 출처에서의 크로스 오리진 요청을 허용합니다.
@RestController // REST 컨트롤러임을 나타냅니다.
@RequestMapping("/api/auth") // '/api/auth' 경로로의 요청을 처리합니다.
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager; // Spring Security의 인증 관리자

    @Autowired
    UserRepository userRepository; // 사용자 정보를 관리하는 레포지토리

    @Autowired
    RoleRepository roleRepository; // 역할 정보를 관리하는 레포지토리

    @Autowired
    PasswordEncoder encoder; // 비밀번호 암호화를 위한 인코더

    @Autowired
    JwtUtils jwtUtils; // JWT 생성 및 검증 유틸리티

    /**
     * 로그인 요청을 처리하고 JWT 쿠키를 생성하여 반환합니다.
     *
     * @param loginRequest 로그인 요청 정보를 담은 객체
     * @return ResponseEntity 로그인 처리 결과
     */
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        // 사용자 인증을 수행합니다.
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication); // 인증 정보를 SecurityContext에 저장합니다.

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal(); // 인증된 사용자의 상세 정보를 가져옵니다.

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails); // JWT 쿠키를 생성합니다.

        List<String> roles = userDetails.getAuthorities().stream() // 사용자의 권한 목록을 가져옵니다.
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()) // JWT 쿠키와 사용자 정보를 반환합니다.
                .body(new UserInfoResponse(
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles));
    }

    /**
     * 회원가입 요청을 처리합니다.
     *
     * @param signUpRequest 회원가입 요청 정보를 담은 객체
     * @return ResponseEntity 회원가입 처리 결과
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest){
        if (userRepository.existsByUsername(signUpRequest.getUsername())){ // 사용자명 중복 확인
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())){ // 이메일 중복 확인
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword())); // 새 사용자 계정 생성

        Set<String> strRoles = signUpRequest.getRole(); // 요청에서 받은 역할 설정
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) { // 역할이 지정되지 않은 경우 기본 역할 설정
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin": // 관리자 역할 설정
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod": // 모더레이터 역할 설정
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default: // 기본 사용자 역할 설정
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles); // 역할 설정
        userRepository.save(user); // 사용자 정보 저장

        return ResponseEntity.ok(new MessageResponse("User registered successfully!")); // 회원가입 성공 응답
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(){
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You've been signed out!"));
    }
}