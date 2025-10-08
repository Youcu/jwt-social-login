package com.hooby.token.system.security.jwt.util;

import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.model.UserPrincipal;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@RequiredArgsConstructor
public class JwtTokenProvider {
    private final SecretKey secretKey;

    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;


    @Value("${jwt.refresh-token-expiration-weeks}")
    private int refreshTokenExpirationWeeks;

    public JwtDto.TokenData createRefreshToken(UserPrincipal userPrincipal, String refreshUuid) {
        JwtDto.TokenPayload payload = JwtDto.TokenPayload.builder()
                .subject(getSubject(userPrincipal))
                .tokenType(TokenType.REFRESH)
                .expiredAt(LocalDateTime.now().plusWeeks(refreshTokenExpirationWeeks))
                .refreshUuid(refreshUuid)
                .build();

        String token = getToken(payload);
        return JwtDto.TokenData.builder()
                .token(token)
                .expiredAt(payload.getExpiredAt())
                .build();
    }

    public JwtDto.TokenData createAccessToken(UserPrincipal userPrincipal, String refreshUuid) {
        JwtDto.TokenPayload payload = JwtDto.TokenPayload.builder()
                .subject(getSubject(userPrincipal))
                .tokenType(TokenType.ACCESS)
                .expiredAt(LocalDateTime.now().plusMinutes(accessTokenExpirationMinutes))
                .role(userPrincipal.getRole())
                .refreshUuid(refreshUuid)
                .build();

        String token = getToken(payload);

        return JwtDto.TokenData.builder()
                .token(token)
                .expiredAt(payload.getExpiredAt())
                .build();
    }

    public JwtDto.TokenPair createTokenPair(UserPrincipal userPrincipal) {
        String refreshUuid = java.util.UUID.randomUUID().toString();
        JwtDto.TokenData accessToken = createAccessToken(userPrincipal, refreshUuid);
        JwtDto.TokenData refreshToken = createRefreshToken(userPrincipal, refreshUuid);

        return JwtDto.TokenPair.of(refreshToken, accessToken);
    }

    private String getSubject(UserPrincipal userPrincipal) {
        // OAuth2 사용자의 경우 userId가 null이므로 username을 subject로 사용
        return userPrincipal.getUserId() != null
                ? userPrincipal.getUserId().toString()
                : userPrincipal.getUsername();
    }

    private String getToken(JwtDto.TokenPayload payload) {
        TokenType tokenType = payload.getTokenType();
        switch (tokenType) {
            case TokenType.ACCESS -> {
                return Jwts.builder()
                        .subject(payload.getSubject())
                        .claim("role", payload.getRole())
                        .claim("refreshUuid", payload.getRefreshUuid())
                        .claim("type", payload.getTokenType())
                        .issuedAt(new Date())
                        .expiration(Date.from(payload.getExpiredAt().atZone(ZoneId.systemDefault()).toInstant()))
                        .signWith(secretKey)
                        .compact();
            }
            case TokenType.REFRESH -> {
                return Jwts.builder()
                        .subject(payload.getSubject())
                        .claim("refreshUuid", payload.getRefreshUuid())
                        .claim("type", payload.getTokenType())
                        .issuedAt(new Date())
                        .expiration(Date.from(payload.getExpiredAt().atZone(ZoneId.systemDefault()).toInstant()))
                        .signWith(secretKey)
                        .compact();
            }
            default -> throw new IllegalArgumentException("⚠️ Invalid Token Type");
        }
    }
}
