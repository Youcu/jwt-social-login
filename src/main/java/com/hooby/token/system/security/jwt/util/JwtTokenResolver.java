package com.hooby.token.system.security.jwt.util;

import com.hooby.token.domain.user.entity.enums.Role;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtTokenResolver {
    private final JwtTokenValidator jwtTokenValidator;

    public Optional<String> parseTokenFromRequest(HttpServletRequest request) {
        try {
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Bearer ")) return Optional.empty();

            return Optional.of(header.substring(7));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public JwtDto.TokenPayload resolveToken(String token) {
        Claims payload = jwtTokenValidator.parseClaimsWithValidation(token).getPayload();
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
