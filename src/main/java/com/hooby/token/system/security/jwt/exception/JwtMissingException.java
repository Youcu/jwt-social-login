package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtMissingException extends JwtBaseException {
    public JwtMissingException() {
        super(ErrorCode.JWT_MISSING);
    }

    public JwtMissingException(String message) {
        super(ErrorCode.JWT_MISSING, message);
    }

    public JwtMissingException(Throwable cause) {
        super(ErrorCode.JWT_MISSING, cause);
    }
}
