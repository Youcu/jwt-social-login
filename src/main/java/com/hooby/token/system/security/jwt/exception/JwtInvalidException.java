package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtInvalidException extends JwtBaseException {
    public JwtInvalidException() {
        super(ErrorCode.JWT_INVALID);
    }

    public JwtInvalidException(String message) {
        super(ErrorCode.JWT_INVALID, message);
    }

    public JwtInvalidException(Throwable cause) {
        super(ErrorCode.JWT_INVALID, cause);
    }
}
