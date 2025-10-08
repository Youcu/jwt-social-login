package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.BaseException;
import com.hooby.token.system.exception.model.ErrorCode;
import lombok.Getter;

@Getter
public class JwtBaseException extends BaseException {
    public JwtBaseException(ErrorCode errorCode) {
        super(errorCode);
    }

    public JwtBaseException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public JwtBaseException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
