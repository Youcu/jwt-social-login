package com.hooby.token.system.security.jwt.util;

import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;

@RequiredArgsConstructor
public class JwtTokenValidator {
    private final SecretKey secretKey;

    /**
     * JWT 토큰의 유효성을 검증합니다.
     * 만료시간, 서명, 형식 등을 모두 검증합니다.
     *
     * @param token 검증할 JWT 토큰
     * @return 유효한 토큰이면 true, 그렇지 않으면 false
     */
    public boolean isValid(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
