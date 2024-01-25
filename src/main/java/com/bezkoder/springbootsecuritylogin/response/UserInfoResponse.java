package com.bezkoder.springbootsecuritylogin.response;

import java.util.List;

public class UserInfoResponse {
    private Long id;
    private String username;
    private String email;
    private List<String> roles; // 역할을 List<String>으로 변경

    public UserInfoResponse(Long id, String username, String email, List<String> roles) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public Long getId(){
        return id;
    }

    public String getUsername(){
        return username;
    }

    public String getEmail(){ // 메소드 이름 수정
        return email;
    }

    public List<String> getRoles(){ // 역할에 대한 getter 메소드 수정
        return roles;
    }
}
