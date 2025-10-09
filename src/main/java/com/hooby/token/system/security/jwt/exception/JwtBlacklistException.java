package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtBlacklistException extends JwtBaseException {
    public JwtBlacklistException() {
        super(ErrorCode.JWT_BLACKLIST);
    }

    public JwtBlacklistException(String message) {
        super(ErrorCode.JWT_BLACKLIST, message);
    }

    public JwtBlacklistException(Throwable cause) {
        super(ErrorCode.JWT_BLACKLIST, cause);
    }
}
