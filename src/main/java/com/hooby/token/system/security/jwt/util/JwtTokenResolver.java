package com.hooby.token.system.security.jwt.util;

import com.hooby.token.domain.user.entity.Role;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.jwt.exception.JwtExpiredException;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.exception.JwtMalformedException;
import com.hooby.token.system.security.jwt.exception.JwtParseException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;
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
        try {
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Bearer ")) return Optional.empty();

            return Optional.of(header.substring(7));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Jws<Claims> parseClaimsWithValidation(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        } catch (SecurityException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new JwtInvalidException(e);
        } catch (MalformedJwtException e) {
            throw new JwtMalformedException(e);
        } catch (ExpiredJwtException e) {
            throw new JwtExpiredException(e);
        }
    }

    public JwtDto.TokenPayload resolveToken(String token) {
        Claims payload = parseClaimsWithValidation(token).getPayload();
        LocalDateTime exp = payload.getExpiration().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();

        String type = payload.get("type", String.class);
        String role = payload.get("role", String.class);

        return JwtDto.TokenPayload.builder()
                .subject(payload.getSubject())
                .expiredAt(exp)
                .tokenType(type == null ? null : TokenType.valueOf(type))
                .role(role == null ? null : Role.valueOf(role))
                .refreshUuid(payload.get("refreshUuid", String.class))
                .jti(payload.getId())
                .build();
    }
}
