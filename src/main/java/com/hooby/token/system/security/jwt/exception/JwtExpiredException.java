package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtExpiredException extends JwtBaseException {
    public JwtExpiredException() {
        super(ErrorCode.JWT_EXPIRED);
    }

    public JwtExpiredException(String message) {
        super(ErrorCode.JWT_EXPIRED, message);
    }

    public JwtExpiredException(Throwable cause) {
        super(ErrorCode.JWT_EXPIRED, cause);
    }
}
