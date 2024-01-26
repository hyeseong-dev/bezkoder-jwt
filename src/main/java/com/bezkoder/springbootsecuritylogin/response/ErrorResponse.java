package com.bezkoder.springbootsecuritylogin.response;

import com.bezkoder.springbootsecuritylogin.exception.ErrorCode;

public class ErrorResponse {
    private ErrorCode errorCode;
    private String errorMessage;

    public String getErrorMessage(){
        return errorMessage;
    }

    public ErrorCode getErrorCode(){
        return errorCode;
    }
}
