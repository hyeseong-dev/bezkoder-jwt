package com.bezkoder.springbootsecuritylogin.exception;

public class CustomException extends RuntimeException{
    private ErrorCode errorCode;
    private String detailMessage;

    public CustomException(ErrorCode errorCode){
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.detailMessage = errorCode.getMessage();
    }

    public CustomException(ErrorCode errorCode, String detailMessage){
        super(detailMessage);
        this.errorCode = errorCode;
        this.detailMessage = detailMessage;
    }
}
