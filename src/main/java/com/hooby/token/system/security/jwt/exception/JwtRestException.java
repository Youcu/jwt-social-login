package com.hooby.token.system.security.jwt.exception;

import com.hooby.token.system.exception.model.RestException;
import com.hooby.token.system.exception.model.ErrorCode;
import lombok.Getter;

@Getter
public class JwtRestException extends RestException {
    public JwtRestException(ErrorCode errorCode) {
        super(errorCode);
    }

    public JwtRestException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public JwtRestException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
