package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtAuthenticationException extends JwtBaseException {
    public JwtAuthenticationException() {
        super(ErrorCode.JWT_AUTHENTICATION_FAILED);
    }

    public JwtAuthenticationException(String message) {
        super(ErrorCode.JWT_AUTHENTICATION_FAILED, message);
    }

    public JwtAuthenticationException(Throwable cause) {
        super(ErrorCode.JWT_AUTHENTICATION_FAILED, cause);
    }
}
