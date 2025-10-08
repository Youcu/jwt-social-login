package com.hooby.token.system.security.jwt.util;

import com.hooby.token.domain.user.entity.Role;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.jwt.exception.JwtExpiredException;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.exception.JwtParseException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtTokenResolver {
    private final SecretKey secretKey;

    public Optional<String> parseTokenFromRequest(HttpServletRequest request) {
        Optional<String> header;
        try {
            header = Optional.ofNullable(request.getHeader("Authorization"));
        } catch (Exception e) {
            header = Optional.empty();
        }

        return header.filter(token -> token.startsWith("Bearer")).map(token -> token.substring(7));
    }

    public Jws<Claims> parseClaims(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new JwtExpiredException(e);
        } catch (SignatureException e) {
            throw new JwtInvalidException(e);
        } catch (Exception e) {
            throw new JwtParseException(e);
        }
    }

    public JwtDto.TokenPayload resolveToken(String token) {
        Claims payload = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();

        LocalDateTime expiration = payload.getExpiration()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        return JwtDto.TokenPayload.builder()
                .subject(payload.getSubject())
                .expiredAt(expiration)
                .tokenType(payload.get("type", TokenType.class))
                .role(payload.get("role", Role.class))
                .refreshUuid(payload.get("refreshUuid", String.class))
                .build();
    }
}
