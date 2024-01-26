package com.bezkoder.springbootsecuritylogin.exception;

public enum ErrorCode {
    NOT_FOUND("요청을 찾을 수 없습니다."),
    DUPLICATED_RESOURCE("중복된 자원이 존재합니다."),
    INTERNAL_SERVER_ERROR("서버에 오류가 발생하였습니다."),
    INVALID_REQUEST("잘못된 요청입니다.");

    private final String message;

    ErrorCode(String message){
        this.message=message;
    }

    public String getMessage(){
        return message;
    }

}
