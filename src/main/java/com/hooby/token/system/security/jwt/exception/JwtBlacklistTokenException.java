package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.ErrorCode;

public class JwtBlacklistTokenException extends JwtBaseException {
    public JwtBlacklistTokenException() {
        super(ErrorCode.JWT_BLACKLIST);
    }

    public JwtBlacklistTokenException(String message) {
        super(ErrorCode.JWT_BLACKLIST, message);
    }

    public JwtBlacklistTokenException(Throwable cause) {
        super(ErrorCode.JWT_BLACKLIST, cause);
    }
}
